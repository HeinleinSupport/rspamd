--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>
Copyright (c) 2026, Carsten Rosenberg <c.rosenberg@heinlein-support.de>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

--[[[
-- @module lua_content/ooxml
-- This module contains heuristics for Office Open XML (OOXML) documents:
-- .docx, .docm, .xlsx, .xlsm, .pptx, .pptm
--
-- OOXML files are ZIP archives containing XML and binary parts.
-- VBA macros are stored in a CFBF blob named "vbaProject.bin".
-- XLM (Excel 4.0) macros live under xl/macrosheets/.
-- This module scans the archive file list to detect these indicators
-- without extracting any file content (rspamd's archive API provides
-- names only).
--
-- Detection:
--   - vbaProject.bin anywhere → has_vbaproject + has_macros
--   - xl/macrosheets/ path prefix → has_xlm_macros + has_macros
--   - xl/externalLinks/ → has_external_links
--   - activeX/ in word/, xl/, or ppt/ → has_activex
--   - File extension ending in 'm' (docm/xlsm/pptm) → has_macros_by_ext
--   - Document type inferred from top-level path prefix (word/, xl/, ppt/)
--
-- All path matching is case-insensitive: OOXML writers use a fixed casing,
-- but a repacked archive can vary it freely and the consuming application
-- does not care.
--]]

local lua_content_util = require "lua_content/util"
local lua_util = require "lua_util"
local N        = "lua_content"

local exports = {}

-- Upper bound on archive entries examined
local OOXML_MAX_FILES = 500

-- Archive path fragments, lowercased for case-insensitive comparison
local VBAPROJECT     = 'vbaproject.bin'
local XLM_PREFIX     = 'xl/macrosheets/'
local EXTLINK_PREFIX = 'xl/externallinks/'
local ACTIVEX_FRAG   = '/activex/'
local WORD_PREFIX    = 'word/'
local XL_PREFIX      = 'xl/'
local PPT_PREFIX     = 'ppt/'

-- -------------------------------------------------------------------------
-- Main processing function
-- -------------------------------------------------------------------------

local function process_ooxml(input, mpart, task)
  if not input or #input == 0 then
    return nil
  end

  -- OOXML files must be served as archives.  If no archive part is available
  -- the file is malformed or was not recognised as ZIP by the mime layer.
  local arch = mpart:get_archive()

  if not arch then
    lua_util.debugm(N, task, 'ooxml: no archive part available')
    return nil
  end

  -- Ask for one more than the cap: get_files() returns min(actual, requested),
  -- so asking for exactly the cap can't tell 500 entries from 5000, and
  -- reporting the latter is the whole point.
  local files = arch:get_files(OOXML_MAX_FILES + 1)

  if not files then
    lua_util.debugm(N, task, 'ooxml: archive returned no file list')
    return nil
  end

  if #files > OOXML_MAX_FILES then
    -- Drop the extra entry again; it only proved there was more. Entries past
    -- the cap are never scanned, so say so rather than report a clean archive.
    files[#files] = nil
    lua_content_util.note_limit(task, 'ooxml', 'files')
  end

  local result = {
    tag                = 'ooxml',
    doc_type           = nil,   -- 'word' | 'excel' | 'ppt' | nil
    has_macros         = false, -- any macro indicator found
    has_vbaproject     = false, -- vbaProject.bin present
    has_xlm_macros     = false, -- Excel 4.0 / XLM macro sheets
    has_external_links = false, -- external data connections
    has_activex        = false, -- ActiveX controls embedded
    has_macros_by_ext  = false, -- file extension signals macro-enabled format
    file_count         = #files,
    urls               = {},
    extract_text       = function(_specific)
      return nil
    end,
  }

  -- Extension-based macro signal (docm / xlsm / pptm end in 'm')
  local detected_ext = mpart:get_detected_ext()

  if detected_ext and detected_ext:sub(-1) == 'm' then
    result.has_macros_by_ext = true
    result.has_macros = true
    lua_util.debugm(N, task, 'ooxml: macro-enabled extension: %s', detected_ext)
  end

  -- Scan file list. Plain (non-pattern) comparisons are used throughout:
  -- these are fixed substrings, so the Lua pattern matcher has nothing to
  -- contribute. Prefix/suffix lengths are derived from the literals so they
  -- cannot drift out of sync with them.
  local debug_on = lua_content_util.debug_enabled()

  for _, fname in ipairs(files) do
    local lname = fname:lower()

    if debug_on then
      lua_util.debugm(N, task, 'ooxml: archive entry: %s', fname)
    end

    -- VBA project binary (present in all macro-enabled OOXML variants)
    if lname:sub(-#VBAPROJECT) == VBAPROJECT then
      result.has_vbaproject = true
      result.has_macros = true
      lua_util.debugm(N, task, 'ooxml: found vbaProject.bin')
    end

    -- XLM / Excel 4.0 macro sheets
    if lname:sub(1, #XLM_PREFIX) == XLM_PREFIX then
      result.has_xlm_macros = true
      result.has_macros = true
      lua_util.debugm(N, task, 'ooxml: found XLM macrosheet: %s', fname)
    end

    -- External data links (used in link-injection and phishing attacks)
    if lname:sub(1, #EXTLINK_PREFIX) == EXTLINK_PREFIX then
      result.has_external_links = true
      lua_util.debugm(N, task, 'ooxml: found external link: %s', fname)
    end

    -- ActiveX controls
    if lname:find(ACTIVEX_FRAG, 1, true) then
      result.has_activex = true
      lua_util.debugm(N, task, 'ooxml: found ActiveX entry: %s', fname)
    end

    -- Infer document type from top-level path prefix (first match wins)
    if not result.doc_type then
      if lname:sub(1, #WORD_PREFIX) == WORD_PREFIX then
        result.doc_type = 'word'
        lua_util.debugm(N, task, 'ooxml: detected doc_type=word')
      elseif lname:sub(1, #XL_PREFIX) == XL_PREFIX then
        result.doc_type = 'excel'
        lua_util.debugm(N, task, 'ooxml: detected doc_type=excel')
      elseif lname:sub(1, #PPT_PREFIX) == PPT_PREFIX then
        result.doc_type = 'ppt'
        lua_util.debugm(N, task, 'ooxml: detected doc_type=ppt')
      end
    end
  end

  lua_util.debugm(N, task,
      'ooxml: result tag=%s doc_type=%s has_macros=%s has_vbaproject=%s ' ..
      'has_xlm=%s has_external=%s has_activex=%s has_by_ext=%s files=%s',
      result.tag, tostring(result.doc_type), result.has_macros,
      result.has_vbaproject, result.has_xlm_macros, result.has_external_links,
      result.has_activex, result.has_macros_by_ext, result.file_count)

  return result
end

--[[[
-- @function ooxml.process(input, mpart, task)
-- Processes an OOXML (ZIP-based Office) file: scans the archive file list
-- for macro indicators, external links, and ActiveX controls.
--
-- Returns a table with fields:
--   tag              'ooxml'
--   doc_type         'word' | 'excel' | 'ppt' | nil
--   has_macros       true if any macro indicator found
--   has_vbaproject   true if vbaProject.bin present in archive
--   has_xlm_macros   true if xl/macrosheets/ entries found
--   has_external_links  true if xl/externalLinks/ entries found
--   has_activex      true if activeX/ entries found
--   has_macros_by_ext   true if file extension ends in 'm'
--   file_count       number of entries in the archive
--   urls             list of extracted URLs (currently always empty)
--]]
exports.process = process_ooxml

return exports
