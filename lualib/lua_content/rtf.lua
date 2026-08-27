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
-- @module lua_content/rtf
-- This module contains heuristics for RTF files.
-- RTF is a common malware delivery vector via embedded OLE objects,
-- binary blobs (\bin), suspicious hex payloads, and exploit-related
-- keywords targeting MS Office equation editor and similar vulnerabilities.
--]]

local lua_content_util = require "lua_content/util"
local lua_util = require "lua_util"
local N = "lua_content"

local exports = {}

-- All RTF indicators are matched in a single trie pass. The order of this
-- list defines the trie pattern indexes, so entries may be appended but not
-- reordered independently of it.
local rtf_patterns = {
  -- OLE object embedding: CVE-2017-11882 (Equation Editor) family and similar
  { 'has_ole_object',          [=[\\\*\\objdata\b]=] },
  { 'has_ole_object',          [=[\\\*\\object\b]=] },
  -- Package object (often used to embed executable files)
  { 'has_ole_object',          [=[\\\*\\objclass\b]=] },
  -- Inline binary blob: \binN <N raw bytes follow>
  { 'has_bin_keyword',         [=[\\bin\d]=] },
  -- Generic field instruction. On its own this says nothing: \fldinst is what
  -- every RTF hyperlink, TOC entry, page number, date and mail-merge field is
  -- built from. It is recorded only so that has_dde can require it alongside
  -- an actual DDE verb below.
  { 'has_field',               [=[\\\*\\fldinst\b]=] },
  -- DDE / DDEAUTO field verb (Dynamic Data Exchange, executes a shell command
  -- on open). DDEAUTO fires without a prompt, plain DDE asks first.
  { 'has_dde_verb',            [=[(?i)\bDDEAUTO\b]=] },
  { 'has_dde_verb',            [=[(?i)\bDDE\s]=] },
  -- Large contiguous hex block (>= 200 hex chars): shellcode or embedded PE.
  -- Legitimate RTF hex is usually short picture data split across many {\pict}
  -- groups.
  { 'has_large_hex',           [=[[0-9a-fA-F]{200,}]=] },
  -- \leveltext / listoverride obfuscation used in some exploits
  { 'has_level_obfuscation',   [=[\\leveltext[^;]{0,200}\\f\d{4,}]=] },
  -- CVE-2025-21298: hex-encoded OLE class name "StaticDib" (ASCII bytes
  -- 53 74 61 74 69 63 44 69 62) found inside \objdata blocks. A malformed
  -- StaticDib embedded object with non-DIB stub data (e.g. four null bytes
  -- instead of a valid BMP/DIB payload) triggers a double-free in
  -- ole32.dll!UtOlePresStmToContentsStm when the RTF is opened by Word or
  -- Outlook (Windows RCE).
  -- See https://github.com/decalage2/oletools/issues/883
  { 'has_staticdib_exploit',   [=[(?i)537461746963446962]=] },
  -- Equation Editor OLE class name, as stored in the \objclass control word
  -- and in the ANSI class-name field of the OLE1 header inside \objdata.
  -- The dashed CLSID text form is NOT used in RTF: objdata holds either the
  -- class name as ASCII or the raw GUID bytes, so the class name is what is
  -- actually reachable without decoding the hex stream.
  { 'has_equation_exploit',    [=[(?i)Equation\.[23]\b]=] },
  -- Same class name hex-encoded inside the \objdata stream:
  -- "Equation.3" = 45 71 75 61 74 69 6f 6e 2e 33
  { 'has_equation_exploit',    [=[(?i)4571756174696f6e2e33]=] },
}

local rtf_trie = lua_content_util.compile_flag_patterns(rtf_patterns)

-- Embedded PE detection.
--
-- A bare search for "4d5a" anywhere in the file is useless: hex is a uniform
-- alphabet, so the four-nibble sequence turns up by chance roughly once per
-- 64 KB of hex and therefore fires on virtually every RTF that carries an
-- ordinary embedded picture. Two things are matched instead, both of which a
-- picture blob will not produce:
--
--   * the PE DOS stub string ("This program cannot be run in DOS mode"),
--     which is present in essentially every real PE image. It is matched both
--     hex-encoded (payload inside an \objdata stream) and as raw bytes
--     (payload embedded through \bin). Because the payload usually sits
--     behind an OLE1 header, the MZ signature itself is rarely at the start of
--     \objdata, so the stub is the reliable marker rather than the magic.
--   * "4d5a" at the very start of an \objdata hex run, for a PE stored
--     without an OLE1 wrapper.
local mz_patterns = {
  -- "This program cannot" hex-encoded
  { 'has_mz_in_hex', [=[(?i)546869732070726f6772616d2063616e6e6f74]=] },
  -- The same stub as raw bytes
  { 'has_mz_in_hex', [=[This program cannot be run in DOS mode]=] },
  -- MZ at the head of an \objdata hex stream
  { 'has_mz_in_hex', [=[(?i)\\\*\\objdata[\s}]{0,64}4d5a[0-9a-f]{10,}]=] },
}

local mz_trie = lua_content_util.compile_flag_patterns(mz_patterns)

local function process_rtf(input, mpart, task)
  if not input or #input == 0 then
    return nil
  end

  -- Kept as rspamd_text: both tries read it in place
  local scan_buf = lua_content_util.limit(input,
      lua_content_util.config.max_processing_size)

  local result = {
    tag = 'rtf',
    has_ole_object = false,
    has_bin_keyword = false,
    has_large_hex = false,
    has_mz_in_hex = false,
    has_dde = false,
    has_equation_exploit = false,
    has_level_obfuscation = false,
    has_staticdib_exploit = false,
    urls = {},
    extract_text = function(_specific)
      return nil
    end,
  }

  -- Intermediate flags that are combined below rather than reported directly
  local flags = {}
  lua_content_util.scan_flags(rtf_trie, rtf_patterns, scan_buf, flags)
  lua_content_util.scan_flags(mz_trie, mz_patterns, scan_buf, flags)

  result.has_ole_object = flags.has_ole_object or false
  result.has_bin_keyword = flags.has_bin_keyword or false
  result.has_large_hex = flags.has_large_hex or false
  result.has_mz_in_hex = flags.has_mz_in_hex or false
  result.has_level_obfuscation = flags.has_level_obfuscation or false
  result.has_staticdib_exploit = flags.has_staticdib_exploit or false
  result.has_equation_exploit = flags.has_equation_exploit or false

  -- DDE requires the field machinery *and* a DDE verb. Requiring both keeps
  -- ordinary hyperlinked documents (which all carry \fldinst) out of the rule.
  result.has_dde = (flags.has_field and flags.has_dde_verb) or false

  lua_util.debugm(N, task,
      'rtf: ole=%s bin=%s large_hex=%s mz=%s dde=%s equation=%s ' ..
      'level_obf=%s staticdib=%s',
      result.has_ole_object, result.has_bin_keyword, result.has_large_hex,
      result.has_mz_in_hex, result.has_dde, result.has_equation_exploit,
      result.has_level_obfuscation, result.has_staticdib_exploit)

  lua_content_util.extract_urls(input, mpart, task, result, 'rtf')

  return result
end

--[[[
-- @function rtf.process(input, mpart, task)
-- Processes an RTF file: detects embedded OLE objects, binary blobs,
-- exploit indicators and extracts URLs.
-- Returns a table with boolean flags:
--   has_ole_object, has_bin_keyword, has_large_hex, has_mz_in_hex,
--   has_dde, has_equation_exploit, has_level_obfuscation, has_staticdib_exploit
-- and urls[] list.
--]]
exports.process = process_rtf

return exports
