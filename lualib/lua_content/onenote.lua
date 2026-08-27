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
-- @module lua_content/onenote
-- This module contains heuristics for Microsoft OneNote (.one) files.
--
-- OneNote became a primary malware delivery vector after Microsoft disabled
-- Office macros by default in 2022. Attackers embed arbitrary executable
-- files (HTA, VBS, JS, EXE, LNK, BAT, PS1 etc.) as clickable "attachments"
-- inside a .one page, overlaid with a fake "click to view" image to trick
-- the user into executing the payload.
--
-- The .one binary format (MS-ONE spec) stores embedded files as
-- FileDataStoreObject structures. The file content is stored verbatim,
-- so magic-byte matching at offset 0 of each payload identifies its type.
--]]

local lua_content_util = require "lua_content/util"
local lua_util = require "lua_util"
local N = "lua_content"

local exports = {}

-- OneNote section file magic (first 16 bytes): E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3
-- Used to confirm we have a genuine .one file, not a misnamed attachment.
local ONENOTE_MAGIC = "\xE4\x52\x5C\x7B\x8C\xD8\xA7\x4D\xAE\xB1\x53\x78\xD0\x29\x96\xD3"

-- FileDataStoreObject GUID (MS-ONE §2.3.1): marker that precedes embedded file data
-- {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
-- Stored little-endian: e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
local FDSO_GUID = "\xE7\x16\xE3\xBD\x65\x26\x11\x45\xA4\xC4\x8D\x4D\x0B\x7A\x9E\xAC"

-- Byte signatures of dangerous embedded file types. These are *magic bytes*
-- and are therefore anchored at offset 0 of the payload: matching them
-- anywhere within the header window would fire on any binary that happens to
-- contain the two-byte sequence "MZ" or "#!" by chance, which for a 512 byte
-- window is roughly a 1.5% hit rate on arbitrary data.
local payload_magic = {
  { "\x4D\x5A",         'exe_dll' },  -- MZ: PE executable / DLL
  { "\xD0\xCF\x11\xE0", 'ole_doc' },  -- OLE2 (legacy Office doc with macros)
  { "PK\x03\x04",       'zip_based' },-- ZIP: OOXML, JAR, APK
  { "\x7FELF",          'elf' },      -- ELF executable
  { "#!",               'shebang' },  -- Shell script
}

-- Textual payload markers. Unlike the magic bytes above these legitimately
-- occur anywhere in the payload, so they are matched over the whole header
-- window with a single trie pass.
local payload_patterns = {
  { 'script_tag', [=[(?i)<script[\s>]]=] },                  -- HTA/HTML dropper
  { 'php',        [=[(?i)<\?php\b]=] },                      -- PHP webshell
  { 'autorun',    [=[(?i)\[autorun\]]=] },                   -- AutoRun INF
  { 'powershell', [=[(?i)powershell\b]=] },                  -- PowerShell script
  { 'wscript',    [=[(?i)wscript|cscript|mshta|cmd\.exe]=] },-- WSH/HTA launchers
}

local payload_trie = lua_content_util.compile_flag_patterns(payload_patterns)

-- Bytes of each embedded payload inspected for type identification
local PAYLOAD_WINDOW = 512

-- Upper bound on embedded files examined per document
local MAX_EMBEDDED_FILES = 64

-- Scan one payload header for known dangerous types.
-- Returns a list of matched labels (strings).
local function scan_embedded_payload(slice)
  local found = {}

  -- Anchored magic byte check
  for _, entry in ipairs(payload_magic) do
    local magic, label = entry[1], entry[2]

    if slice:sub(1, #magic) == magic then
      found[#found + 1] = label
      break -- magic bytes at offset 0 are mutually exclusive
    end
  end

  -- Unanchored textual markers, one trie pass
  local hits = {}
  lua_content_util.scan_flags(payload_trie, payload_patterns, slice, hits)

  for _, entry in ipairs(payload_patterns) do
    if hits[entry[1]] then
      found[#found + 1] = entry[1]
    end
  end

  return found
end

-- Walk the raw .one binary looking for FileDataStoreObject GUIDs.
-- When found, extract the file size (uint64 LE at offset +16) and scan
-- the payload at offset +24 for dangerous magic bytes.
-- Returns a list of { offset, size, types[] } entries.
local function find_embedded_files(input)
  local results = {}
  local guid = FDSO_GUID
  local guid_len = #guid
  local input_len = #input
  local pos = 1

  while pos <= input_len - guid_len do
    local found_at = input:find(guid, pos, true)

    if not found_at then
      break
    end

    -- FileDataStoreObject layout (MS-ONE §2.3.1):
    --  [0..15]  = FileDataStoreObject GUID (16 bytes)
    --  [16..23] = cbLength: uint64 LE (8 bytes) — byte count of file data
    --  [24..]   = file data bytes
    local data_offset = found_at + guid_len + 8 -- skip GUID + cbLength field

    if data_offset <= input_len then
      -- Read cbLength (little-endian uint64; cap at uint32 for Lua portability)
      local b1, b2, b3, b4 = input:byte(found_at + guid_len,
          found_at + guid_len + 3)
      local sz = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216

      if sz > 0 and sz < 50 * 1024 * 1024 and data_offset + sz - 1 <= input_len then
        local slice_end = data_offset + math.min(sz, PAYLOAD_WINDOW) - 1
        local slice = input:sub(data_offset, slice_end)

        results[#results + 1] = {
          offset = found_at,
          size   = sz,
          types  = scan_embedded_payload(slice),
        }

        if #results >= MAX_EMBEDDED_FILES then
          break
        end
      end
    end

    pos = found_at + 1
  end

  return results
end

local function process_onenote(input, mpart, task)
  if not input or #input < #ONENOTE_MAGIC then
    return nil
  end

  -- Verify OneNote magic (first 16 bytes) before materialising anything:
  -- :sub() on an rspamd_text is a zero-copy span
  if tostring(input:sub(1, 16)) ~= ONENOTE_MAGIC then
    lua_util.debugm(N, task, 'onenote: magic mismatch, skipping')
    return nil
  end

  local result = {
    tag = 'onenote',
    has_embedded_files = false,
    embedded_files = {},   -- list of { offset, size, types[] }
    has_executable = false,
    has_script = false,
    has_ole = false,
    urls = {},
    extract_text = function(_specific) return nil end,
  }

  -- The GUID walk needs absolute offsets across repeated searches, which is
  -- what plain Lua string semantics give (rspamd_text:find() reports offsets
  -- relative to its `init` argument), so materialise a bounded copy here
  local buf = lua_content_util.to_string(input,
      lua_content_util.config.max_processing_size)

  local embedded = find_embedded_files(buf)

  if #embedded > 0 then
    local debug_on = lua_content_util.debug_enabled()
    result.has_embedded_files = true
    result.embedded_files = embedded

    for _, ef in ipairs(embedded) do
      if debug_on then
        lua_util.debugm(N, task,
            'onenote: embedded file at offset %s, size %s, types: %s',
            ef.offset, ef.size, table.concat(ef.types, ','))
      end

      for _, t in ipairs(ef.types) do
        if t == 'exe_dll' or t == 'elf' then
          result.has_executable = true
        elseif t == 'script_tag' or t == 'shebang' or
            t == 'powershell' or t == 'wscript' or
            t == 'php' or t == 'autorun' then
          result.has_script = true
        elseif t == 'ole_doc' then
          result.has_ole = true
        end
      end
    end
  end

  -- URL extraction (remote tracking images, download links)
  lua_content_util.extract_urls(buf, mpart, task, result, 'onenote')

  return result
end

--[[[
-- @function onenote.process(input, mpart, task)
-- Processes a OneNote (.one) file: scans for embedded file payloads using
-- magic-byte detection and extracts URLs.
-- Returns a table with:
--   has_embedded_files  - at least one FileDataStoreObject found
--   embedded_files[]    - list of { offset, size, types[] }
--   has_executable      - MZ/ELF payload embedded
--   has_script          - script (HTA, VBS, PS1, JS, PHP ...) embedded
--   has_ole             - OLE2 document (legacy Office) embedded
--   urls[]              - URLs found in document body
--]]
exports.process = process_onenote

return exports
