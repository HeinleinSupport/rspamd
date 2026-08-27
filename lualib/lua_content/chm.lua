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
-- @module lua_content/chm
-- This module detects Microsoft Compiled HTML Help (CHM) attachments.
--
-- CHM files use the "ITSF" (IT Storage File) format introduced in Windows 98.
-- The format is documented in MS-CHM but uses LZX-compressed internal sections,
-- making deep content extraction non-trivial.
--
-- Risk profile (2024-2025):
--   CHM is an active phishing and APT delivery vector used by families such
--   as Bumblebee and ValleyRAT.  Windows hh.exe executes embedded HTML and
--   Script inside CHM files without any sandbox.  CHM files do not receive
--   Mark-of-the-Web (MOTW) from most archive containers, so they are almost
--   always delivered inside a ZIP, ISO, or IMG outer container.
--   Legitimate CHM attachments in email are virtually non-existent.
--
-- Detection approach:
--   Validate ITSF magic (4 bytes) and version (LE uint32, must be 2 or 3).
--   No further parsing is performed -- the presence signal alone justifies
--   a high-score rule.  Only the first 8 bytes are ever read, so the part is
--   never copied out of its rspamd_text.
--
-- Why lua_content and not the mime_types plugin:
--   mime_types scores by file extension only.  This module validates the
--   actual ITSF magic bytes, so it fires correctly when:
--     * the Content-Type header is application/octet-stream (common for CHM
--       inside archives or from naive MUAs),
--     * the file extension is absent or renamed,
--     * the MIME type is a registered CHM type but the content is something
--       else (anti-evasion / false-positive protection).
--   Additionally, if URL extraction from CHM internal HTML streams becomes
--   feasible in the future (requires LZX decompression, currently not
--   implemented), the infrastructure (urls table, task:inject_url pattern)
--   is already in place here.
--]]

local lua_util = require "lua_util"
local N        = "lua_content"

local exports = {}

-- ITSF container magic: first 4 bytes of every CHM file
local ITSF_MAGIC = { 0x49, 0x54, 0x53, 0x46 } -- "ITSF"

-- Minimum valid size: 4 (magic) + 4 (version LE uint32)
local CHM_MIN_SIZE = 8

-- Known ITSF format versions:
--   2 = Windows 98 / 2000 era
--   3 = Windows XP and later (by far the most common)
local VALID_VERSIONS = { [2] = true, [3] = true }

local function process_chm(input, _mpart, task)
  if not input or #input < CHM_MIN_SIZE then
    return nil
  end

  -- Read the header directly: :byte() works identically on an rspamd_text and
  -- on a Lua string, so a multi-megabyte CHM is never materialised in the Lua
  -- heap just to check an eight byte header.
  local m1, m2, m3, m4, v0, v1, v2, v3 = input:byte(1, 8)

  if m1 ~= ITSF_MAGIC[1] or m2 ~= ITSF_MAGIC[2]
      or m3 ~= ITSF_MAGIC[3] or m4 ~= ITSF_MAGIC[4] then
    lua_util.debugm(N, task, 'chm: magic mismatch')
    return nil
  end

  -- Version field: LE uint32 at bytes 5-8 (immediately after the magic)
  local version = v0 + v1 * 256 + v2 * 65536 + v3 * 16777216

  if not VALID_VERSIONS[version] then
    lua_util.debugm(N, task, 'chm: unsupported ITSF version: %s', version)
    return nil
  end

  lua_util.debugm(N, task, 'chm: detected ITSF v%s (%s bytes)', version, #input)

  return {
    tag     = 'chm',
    version = version,
    urls    = {},
    extract_text = function(_specific)
      return nil
    end,
  }
end

--[[[
-- @function chm.process(input, mpart, task)
-- Validates a CHM/ITSF container by checking magic and version.
-- Returns a table with:
--   tag      'chm'
--   version  2 or 3
--   urls     {} (always empty)
-- Returns nil if the input is not a valid CHM file.
--]]
exports.process = process_chm

return exports
