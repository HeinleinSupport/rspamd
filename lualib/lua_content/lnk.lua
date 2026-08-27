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
-- @module lua_content/lnk
-- This module contains heuristics for Windows Shortcut (.lnk / MS-SHLLINK) files.
--
-- LNK files became a dominant initial-access vector after Microsoft disabled
-- Office macros from the Internet in 2022. Campaigns delivering Qakbot, IcedID,
-- Emotet, Bumblebee, Latrodectus and many stealers ship LNK files inside
-- ZIP/ISO/IMG archives. The shortcut typically launches cmd.exe, powershell.exe
-- or another LOLBin with a long encoded command that downloads or executes the
-- next-stage payload.
--
-- Format reference: [MS-SHLLINK] — Windows Shell Link (.lnk) Binary File Format
-- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink
--
-- Parsing strategy:
--   Header (76 bytes) → LinkFlags → skip IDList → extract target from LinkInfo
--   → read StringData (WorkingDir, Arguments, IconLocation)
--   → apply LOLBin + suspicious-argument heuristics
--
-- The Shell ItemID List is skipped in its entirety — its nested shell-item
-- structures are complex binary and not needed for the heuristics below.
--]]

local rspamd_regexp = require "rspamd_regexp"
local lua_content_util = require "lua_content/util"
local bit         = require "bit"
local lua_util    = require "lua_util"
local N           = "lua_content"

local exports = {}

-- -------------------------------------------------------------------------
-- LNK header magic
-- HeaderSize (4 bytes: 0x4C 0x00 0x00 0x00) + LinkCLSID (16 bytes)
-- CLSID {00021401-0000-0000-C000-000000000046} in mixed-endian storage:
--   Data1 uint32 LE: 01 14 02 00
--   Data2 uint16 LE: 00 00
--   Data3 uint16 LE: 00 00
--   Data4 bytes:     C0 00 00 00 00 00 00 46
-- -------------------------------------------------------------------------
local LNK_MAGIC = "\x4C\x00\x00\x00"
    .. "\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"

-- LinkFlags bits (MS-SHLLINK §2.1.1)
local LF_HAS_TARGET_IDLIST  = 0x00000001  -- section follows header
local LF_HAS_LINK_INFO      = 0x00000002  -- LinkInfo structure present
local LF_HAS_NAME           = 0x00000004  -- NAME_STRING in StringData
local LF_HAS_RELATIVE_PATH  = 0x00000008  -- RELATIVE_PATH in StringData
local LF_HAS_WORKING_DIR    = 0x00000010  -- WORKING_DIR in StringData
local LF_HAS_ARGUMENTS      = 0x00000020  -- COMMAND_LINE_ARGUMENTS in StringData
local LF_HAS_ICON_LOCATION  = 0x00000040  -- ICON_LOCATION in StringData
local LF_IS_UNICODE         = 0x00000080  -- StringData encoded as UTF-16LE

-- -------------------------------------------------------------------------
-- Compiled patterns — evaluated once at module load time
-- -------------------------------------------------------------------------

-- Common "living off the land" binaries abused in malware LNK files
local lolbin_re = rspamd_regexp.create_cached(
    [=[(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|msiexec|]=]
    .. [=[forfiles|bitsadmin|certutil|wmic|installutil|regasm|regsvcs|msbuild|]=]
    .. [=[cmstp|odbcconf|pcalua|schtasks|explorer|bash|hh)\.exe\b]=],
    'i')

-- Argument-level indicators, compiled into a single trie. The order of this
-- list defines the trie pattern indexes, so entries may be appended but not
-- reordered independently of it.
--
-- Every pattern is case-insensitive: an argument string reaches us exactly as
-- its author wrote it, and the Windows shell does not care about case, so any
-- case-sensitive pattern here is just an evasion opportunity.
local arg_patterns = {
  -- -EncodedCommand / -e  with a base64 blob: PowerShell in-memory execution
  { 'encoded_cmd', [=[(?i)-(?:enc(?:odedcommand)?|e)\s+[A-Za-z0-9+/]{20,}]=] },
  -- -WindowStyle Hidden / -w hidden: window-style evasion
  { 'hidden',      [=[(?i)-w(?:indowstyle)?\s+hid]=] },
  -- -NoProfile / -NonInteractive: reduces PS startup noise
  { 'noprofile',   [=[(?i)-no(?:p(?:rofile)?|ni(?:nteractive)?)]=] },
  -- IEX / Invoke-Expression: in-memory code execution
  { 'iex',         [=[(?i)iex\b|invoke-expression\b]=] },
  -- .NET WebClient download methods
  { 'download',    [=[(?i)downloadstring|downloadfile|net\.webclient]=] },
  -- bitsadmin: LOLBin downloader / background transfer
  { 'bitsadmin',   [=[(?i)bitsadmin\b]=] },
  -- certutil -decode / -urlcache: LOLBin decoder/downloader
  { 'certutil',    [=[(?i)certutil\b]=] },
  -- Remote URL (http/https) embedded in arguments
  { 'remote_url',  [=[(?i)https?://\S{8,}]=] },
  -- cmd /c or cmd /k: shell command execution
  { 'cmd_c',       [=[(?i)cmd(?:\.exe)?\s+/[ck](?:\s|$)]=] },
  -- Large base64 blob: embedded payload or second-stage encoded command
  { 'base64_blob', [=[[A-Za-z0-9+/]{100,}={0,2}]=] },
}

local arg_trie = lua_content_util.compile_flag_patterns(arg_patterns)

-- Icon extensions used to disguise a cmd/ps LNK as a document or image
local doc_icon_re = rspamd_regexp.create_cached(
    [=[\.(?:pdf|docx?|xlsx?|pptx?|png|jpe?g|gif|ico|txt|zip)$]=], 'i')

-- -------------------------------------------------------------------------
-- Binary reading helpers
-- All positions are 1-indexed (Lua convention).
-- -------------------------------------------------------------------------

local function read_u16(s, pos)
  local b0, b1 = s:byte(pos, pos + 1)
  if not b0 or not b1 then return nil end
  return b0 + b1 * 256
end

local function read_u32(s, pos)
  local b0, b1, b2, b3 = s:byte(pos, pos + 3)
  if not b0 or not b1 or not b2 or not b3 then return nil end
  return b0 + b1 * 256 + b2 * 65536 + b3 * 16777216
end

-- Read a null-terminated ANSI (C) string starting at 1-indexed pos.
local function read_cstring(s, pos)
  if pos > #s then return nil end
  local nul = s:find('\0', pos, true)
  if nul then
    return s:sub(pos, nul - 1)
  end
  return s:sub(pos)
end

-- Read UTF-16LE string of `count` code units at 1-indexed pos.
-- Returns an ASCII approximation; non-ASCII characters become '?'.
local function read_utf16le(s, pos, count)
  local len = #s
  local chars = {}
  for i = 0, count - 1 do
    local cp = pos + i * 2
    if cp + 1 > len then break end
    local lo, hi = s:byte(cp, cp + 1)
    if not lo then break end
    if lo == 0 and hi == 0 then
      break -- null terminator
    elseif hi == 0 and lo >= 32 and lo < 128 then
      chars[#chars + 1] = string.char(lo)
    else
      chars[#chars + 1] = '?'
    end
  end
  return table.concat(chars)
end

-- Read one StringData section at 1-indexed pos.
-- Returns (string_value, next_pos).  string_value may be "" on empty section.
local function read_string_section(s, pos, is_unicode)
  local count = read_u16(s, pos)
  if not count then return '', pos end
  local data_pos = pos + 2
  local s_len = #s
  if is_unicode then
    local str_val = read_utf16le(s, data_pos, count)
    return str_val, data_pos + count * 2
  else
    local end_pos = data_pos + count - 1
    if end_pos > s_len then end_pos = s_len end
    return s:sub(data_pos, end_pos), data_pos + count
  end
end

-- Skip one StringData section at pos; return next pos.
local function skip_string_section(s, pos, is_unicode)
  local count = read_u16(s, pos)
  if not count then return pos end
  if is_unicode then
    return pos + 2 + count * 2
  else
    return pos + 2 + count
  end
end

-- -------------------------------------------------------------------------
-- Main processor
-- -------------------------------------------------------------------------

local function process_lnk(input, mpart, task)
  if not input or #input < 76 then
    return nil
  end

  -- Validate HeaderSize + LinkCLSID (first 20 bytes) before materialising
  -- anything: :sub() on an rspamd_text is a zero-copy span
  if tostring(input:sub(1, 20)) ~= LNK_MAGIC then
    lua_util.debugm(N, task, 'lnk: magic mismatch')
    return nil
  end

  -- The structure walk needs random access at absolute offsets, so a bounded
  -- copy is materialised once here. A shortcut that large is already far past
  -- anything the format legitimately produces.
  input = lua_content_util.to_string(input,
      lua_content_util.config.max_processing_size)

  local result = {
    tag                 = 'lnk',
    has_lolbin          = false,
    has_suspicious_args = false,
    has_encoded_cmd     = false,
    has_hidden          = false,
    has_download        = false,
    has_remote_url      = false,
    has_long_args       = false,
    has_icon_mismatch   = false,
    file_size           = #input,
    target_path         = nil,
    working_dir         = nil,
    arguments           = nil,
    icon_location        = nil,
    urls                = {},
    extract_text        = function(_specific) return nil end,
  }

  -- LinkFlags at bytes 21–24 (1-indexed); offset 20 (0-indexed)
  local link_flags = read_u32(input, 21)
  if not link_flags then
    lua_util.debugm(N, task, 'lnk: cannot read LinkFlags')
    return result
  end

  local is_unicode      = bit.band(link_flags, LF_IS_UNICODE) ~= 0
  local has_idlist      = bit.band(link_flags, LF_HAS_TARGET_IDLIST) ~= 0
  local has_link_info   = bit.band(link_flags, LF_HAS_LINK_INFO) ~= 0
  local has_name        = bit.band(link_flags, LF_HAS_NAME) ~= 0
  local has_rel_path    = bit.band(link_flags, LF_HAS_RELATIVE_PATH) ~= 0
  local has_working_dir = bit.band(link_flags, LF_HAS_WORKING_DIR) ~= 0
  local has_arguments   = bit.band(link_flags, LF_HAS_ARGUMENTS) ~= 0
  local has_icon_loc    = bit.band(link_flags, LF_HAS_ICON_LOCATION) ~= 0

  lua_util.debugm(N, task,
      'lnk: flags=0x%x unicode=%s idlist=%s linkinfo=%s workdir=%s args=%s icon=%s',
      link_flags, is_unicode, has_idlist, has_link_info,
      has_working_dir, has_arguments, has_icon_loc)

  -- pos: current parse position (1-indexed); starts right after the 76-byte header
  local pos       = 77
  local input_len = #input

  -- -----------------------------------------------------------------------
  -- Skip LinkTargetIDList
  -- -----------------------------------------------------------------------
  if has_idlist then
    if pos + 1 > input_len then
      lua_util.debugm(N, task, 'lnk: truncated reading IDListSize')
      return result
    end
    local idlist_size = read_u16(input, pos)
    if not idlist_size then
      return result
    end
    pos = pos + 2 + idlist_size
    if pos > input_len + 1 then
      lua_util.debugm(N, task, 'lnk: IDList extends beyond end of file')
      return result
    end
  end

  -- -----------------------------------------------------------------------
  -- Parse LinkInfo → extract local target path
  -- -----------------------------------------------------------------------
  if has_link_info then
    if pos + 3 > input_len then
      lua_util.debugm(N, task, 'lnk: truncated at LinkInfo')
      return result
    end
    local li_size = read_u32(input, pos)
    if not li_size or li_size < 28 then
      lua_util.debugm(N, task, 'lnk: invalid LinkInfoSize: %s', tostring(li_size))
      if li_size and li_size > 0 then
        pos = pos + li_size
      else
        return result
      end
    else
      -- LocalBasePathOffset is at LinkInfo+0x10 (1-indexed: pos+16)
      local local_base_offset = read_u32(input, pos + 16)
      if local_base_offset and local_base_offset < li_size then
        local path_pos = pos + local_base_offset
        if path_pos <= input_len then
          result.target_path = read_cstring(input, path_pos)
          lua_util.debugm(N, task, 'lnk: target_path=%s', result.target_path)
        end
      end
      pos = pos + li_size
    end
  end

  -- -----------------------------------------------------------------------
  -- Parse StringData sections (MS-SHLLINK §2.4, order fixed by spec):
  --   NAME_STRING, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGUMENTS,
  --   ICON_LOCATION
  -- -----------------------------------------------------------------------
  if pos <= input_len then
    -- HasName (skip)
    if has_name then
      pos = skip_string_section(input, pos, is_unicode)
    end

    -- HasRelativePath (skip)
    if has_rel_path and pos <= input_len then
      pos = skip_string_section(input, pos, is_unicode)
    end

    -- HasWorkingDir
    if has_working_dir and pos <= input_len then
      local v, newpos = read_string_section(input, pos, is_unicode)
      result.working_dir = v ~= '' and v or nil
      pos = newpos
      lua_util.debugm(N, task, 'lnk: working_dir=%s', result.working_dir)
    end

    -- HasArguments
    if has_arguments and pos <= input_len then
      local v, newpos = read_string_section(input, pos, is_unicode)
      result.arguments = v ~= '' and v or nil
      pos = newpos
      lua_util.debugm(N, task, 'lnk: arguments=%s', result.arguments)
    end

    -- HasIconLocation (last section we read; pos not needed afterwards)
    if has_icon_loc and pos <= input_len then
      local v = read_string_section(input, pos, is_unicode)
      result.icon_location = v ~= '' and v or nil
      lua_util.debugm(N, task, 'lnk: icon_location=%s', result.icon_location)
    end
  end

  -- -----------------------------------------------------------------------
  -- Heuristics
  -- -----------------------------------------------------------------------

  -- LOLBin check: scan target path, working dir and arguments
  for _, s in ipairs({
    result.target_path  or '',
    result.working_dir  or '',
    result.arguments    or '',
  }) do
    if s ~= '' and lolbin_re:match(s, true) then
      result.has_lolbin = true
      lua_util.debugm(N, task, 'lnk: LOLBin match in: %s', s)
      break
    end
  end

  -- Suspicious argument patterns (all applied to the arguments string only),
  -- evaluated in a single trie pass
  local args = result.arguments

  if args then
    if #args > 200 then
      result.has_long_args = true
      lua_util.debugm(N, task, 'lnk: long arguments (%s chars)', #args)
    end

    local hits = {}
    lua_content_util.scan_flags(arg_trie, arg_patterns, args, hits)

    result.has_encoded_cmd = hits.encoded_cmd or false
    result.has_hidden      = hits.hidden or false
    result.has_download    = hits.download or false
    result.has_remote_url  = hits.remote_url or false

    -- Any of these on their own marks the arguments as suspicious
    result.has_suspicious_args = (hits.encoded_cmd or hits.hidden
        or hits.noprofile or hits.iex or hits.download or hits.bitsadmin
        or hits.certutil or hits.remote_url or hits.cmd_c
        or hits.base64_blob) or false

    lua_util.debugm(N, task,
        'lnk: args encoded=%s hidden=%s noprofile=%s iex=%s download=%s ' ..
        'bitsadmin=%s certutil=%s url=%s cmd_c=%s b64=%s',
        hits.encoded_cmd, hits.hidden, hits.noprofile, hits.iex,
        hits.download, hits.bitsadmin, hits.certutil, hits.remote_url,
        hits.cmd_c, hits.base64_blob)
  end

  -- Icon mismatch: LNK disguised as a document/image via a fake icon path.
  -- Attackers set icon to e.g. "C:\Windows\system32\shell32.dll,1" or a
  -- direct path like "C:\Users\Public\invoice.pdf" while the target is cmd.exe.
  if result.target_path and result.icon_location then
    local target_base = result.target_path:match('[^\\/]+$') or result.target_path
    local icon_base   = result.icon_location:match('[^\\/]+$') or result.icon_location
    if target_base:lower() ~= icon_base:lower()
        and doc_icon_re:match(icon_base, true) then
      result.has_icon_mismatch = true
      lua_util.debugm(N, task,
          'lnk: icon mismatch: target_base=%s icon_base=%s',
          target_base, icon_base)
    end
  end

  -- URL extraction: scan argument and path strings for injected URLs
  local url_corpus = table.concat({
    result.arguments     or '',
    result.working_dir   or '',
    result.target_path   or '',
    result.icon_location or '',
  }, ' ')

  if #url_corpus > 0 then
    lua_content_util.extract_urls(url_corpus, mpart, task, result, 'lnk')
  end

  return result
end

--[[[
-- @function lnk.process(input, mpart, task)
-- Processes a Windows Shortcut (.lnk / MS-SHLLINK) file.
-- Returns a table with:
--   tag = 'lnk'
--   has_lolbin          - target path / arguments reference a LOLBin
--   has_suspicious_args - arguments contain one or more suspicious patterns
--   has_encoded_cmd     - -EncodedCommand / -e base64 blob (PowerShell evasion)
--   has_hidden          - -WindowStyle Hidden (execution evasion)
--   has_download        - .NET WebClient download method in arguments
--   has_remote_url      - http/https URL present in arguments
--   has_long_args       - command-line arguments exceed 200 characters
--   has_icon_mismatch   - icon path uses a document/image extension while
--                         target is a different file (classic disguise technique)
--   file_size           - raw size of the LNK file in bytes (>5 KB is unusual
--                         for legitimate shortcuts and may indicate an embedded
--                         payload or extra data appended after the structure)
--   target_path         - extracted local base path from LinkInfo (ANSI, or nil)
--   working_dir         - WORKING_DIR StringData value (or nil)
--   arguments           - COMMAND_LINE_ARGUMENTS StringData value (or nil)
--   icon_location       - ICON_LOCATION StringData value (or nil)
--   urls[]              - URLs found anywhere in the shortcut content
--]]
exports.process = process_lnk

return exports
