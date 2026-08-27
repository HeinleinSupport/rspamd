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
-- @module lua_content/cfbf
-- This module contains heuristics for Microsoft Compound Binary File Format
-- (OLE2/CFBF) documents: legacy .doc, .xls, .ppt, and .msg files.
--
-- The CFBF format (MS-CFB spec) is a container of named directory entries
-- organised as a tree of "storages" (directories) and "streams" (files).
-- VBA macros are stored as streams inside the "VBA" or "_VBA_PROJECT_CUR"
-- storage. This module detects VBA presence by scanning directory entry
-- names (UTF-16LE encoded, 128 bytes per entry) without requiring full
-- FAT/mini-FAT sector chain traversal.
--
-- Additionally, a raw keyword scan is performed when VBA storages are found
-- to detect auto-execution triggers and execution primitives that are visible
-- in plain ASCII even without OVBA decompression (MS-OVBA §2.4).
--
-- Detection approach (Option A — no FAT traversal, no OVBA decompression):
--   1. Validate CFBF magic and parse the header (512 bytes)
--   2. Follow the directory stream's FAT sector chain; each entry is 128 bytes.
--   3. Decode each directory entry name from UTF-16LE once and prefix-match it
--      to detect:
--      - VBA storages/streams (has_vba)
--      - Document type (doc_type: 'word', 'excel', 'ppt', 'msg')
--   4. Scan raw bytes for DDE field markers (has_dde)
--   5. If VBA detected, scan raw bytes for auto-exec + execution keywords
--      (has_suspicious_vba)
--   6. Extract URLs from the raw buffer via binary-safe rspamd_url scan.
--      This reaches URLs held as ANSI/UTF-8 bytes: hyperlink strings in the
--      plain-text streams of Word/Excel/PPT, and MSG property streams stored
--      in their ANSI (PT_STRING8) form.  URLs in UTF-16LE property streams
--      (the PT_UNICODE "_W" variants Outlook normally writes) and in
--      LZFu-compressed RTF (PR_RTF_COMPRESSED) are not byte-visible and are
--      silently skipped.
--]]

local lua_content_util = require "lua_content/util"
local bit               = require "bit"
local lua_util          = require "lua_util"
local N                 = "lua_content"

local exports = {}

-- CFBF compound file magic (first 8 bytes of every CFBF file)
local CFBF_MAGIC = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

-- Minimum valid file size: one full 512-byte header sector
local CFBF_MIN_SIZE = 512

-- Byte-order mark at header offset 0x1C: 0xFFFE means little-endian, which is
-- the only layout MS-CFB defines (and the only one the readers below assume)
local CFBF_BOM_LE = 0xFFFE

-- MS-CFB §2.2 permits a sector shift of 9 (512 byte sectors, major version 3)
-- or 12 (4096 byte sectors, major version 4). A slightly wider range is
-- accepted for tolerance, but it stays bounded: an unchecked shift would give
-- a multi-gigabyte sector size and turn the per-sector loops below into
-- effectively unbounded iteration.
local CFBF_MIN_SECTOR_SHIFT = 7
local CFBF_MAX_SECTOR_SHIFT = 16

-- Upper bound on directory sectors walked, so that a crafted FAT chain
-- cannot turn the directory walk into a long loop
local CFBF_MAX_DIR_SECTORS = 1024

-- -------------------------------------------------------------------------
-- Directory-entry names indicating VBA macro presence.
-- Present in both doc/xls/ppt and msg (Outlook form scripts).
-- Matched as case-insensitive prefixes of the decoded entry name.
-- "_vba_project" already covers "_vba_project_cur".
-- -------------------------------------------------------------------------
local vba_dir_prefixes = {
  "vba",
  "_vba_project",
  "macros",
}

-- Document-type identifying stream names.
-- MSG (Outlook): MAPI property streams are named "__substg1.0_PPPPTTTT"
-- (where PPPP = property ID, TTTT = type tag).  The 12-char prefix
-- "__substg1.0_" is unique to Outlook MSG files.  The root property stream
-- "__properties_version1.0" is present in every MSG container.
local doc_dir_prefixes = {
  { 'word',  "worddocument" },
  { 'excel', "workbook" },
  { 'excel', "book" },
  { 'ppt',   "powerpoint document" },
  { 'ppt',   "current user" },
  { 'msg',   "__substg1.0_" },
  { 'msg',   "__properties_version1.0" },
}

-- -------------------------------------------------------------------------
-- Raw-content scanning patterns (single trie pass each)
-- -------------------------------------------------------------------------

-- DDE field markers: \x13 is the field-begin control code in RTF/OLE streams.
-- DDEAUTO executes shell commands silently on open; DDE requires user confirm.
local dde_patterns = {
  { 'has_dde', [=[(?i)\x13\s*DDEAUTO\b]=] },
  { 'has_dde', [=[(?i)\x13\s*DDE\b]=] },
}

local dde_trie = lua_content_util.compile_flag_patterns(dde_patterns)

-- Auto-execution triggers and execution primitives that appear in plain ASCII
-- within CFBF (stored in the p-code name table, not VBA-compressed source).
-- Both classes must be present before the document is called suspicious.
local vba_patterns = {
  { 'autoexec', [=[(?i)AutoOpen|Auto_Open|Workbook_Open|Document_Open|AutoExec|AutoClose|Auto_Close]=] },
  { 'exec',     [=[(?i)Shell\s*\(|CreateObject\s*\(|WScript\.Shell|Environ\s*\(|ShellExecute\s*\(]=] },
}

local vba_trie = lua_content_util.compile_flag_patterns(vba_patterns)

-- -------------------------------------------------------------------------
-- Binary reading helpers (plain Lua string, 1-indexed)
-- -------------------------------------------------------------------------

local function read_u16(s, pos)
  local b0, b1 = s:byte(pos, pos + 1)

  if not b0 or not b1 then
    return nil
  end

  return b0 + b1 * 256
end

local function read_u32(s, pos)
  local b0, b1, b2, b3 = s:byte(pos, pos + 3)

  if not b0 or not b1 or not b2 or not b3 then
    return nil
  end

  return b0 + b1 * 256 + b2 * 65536 + b3 * 16777216
end

local CFBF_ENDOFCHAIN = 0xFFFFFFFE
local CFBF_FREESECT = 0xFFFFFFFF

-- Decode a UTF-16LE directory entry name to lowercase ASCII.
-- `name_len` is the byte count from the entry's NameLength field (includes the
-- terminating NUL). One table plus one concat per entry, rather than a
-- substring allocation per candidate pattern.
local function decode_entry_name(s, offset, name_len)
  if name_len < 4 or name_len > 64 then
    return nil
  end

  local chars = {}

  for i = 0, math.floor(name_len / 2) - 1 do
    local lo, hi = s:byte(offset + i * 2, offset + i * 2 + 1)

    if not lo or not hi or (lo == 0 and hi == 0) then
      break
    end

    if hi == 0 and lo >= 32 and lo < 127 then
      -- ASCII: fold to lowercase for prefix matching
      if lo >= 65 and lo <= 90 then
        lo = lo + 32
      end

      chars[#chars + 1] = string.char(lo)
    else
      chars[#chars + 1] = '?'
    end
  end

  if #chars == 0 then
    return nil
  end

  return table.concat(chars)
end

local function name_has_vba(name)
  for _, prefix in ipairs(vba_dir_prefixes) do
    if name:sub(1, #prefix) == prefix then
      return true
    end
  end

  return false
end

local function name_doc_type(name)
  for _, entry in ipairs(doc_dir_prefixes) do
    if name:sub(1, #entry[2]) == entry[2] then
      return entry[1]
    end
  end

  return nil
end

-- Byte offset (1-based, for string indexing) of the start of sector `sec_id`.
--
-- MS-CFB 2.2: the header is a 512-byte structure that occupies the *first
-- sector* of the file, and when the sector size is larger than 512 the header
-- is padded with zeros to fill it. Sector 0 therefore begins one whole sector
-- into the file, not at byte 512 - the two only coincide for the 512-byte
-- sectors of major version 3. Hardcoding 512 puts every read 3584 bytes off on
-- a major version 4 (4096-byte sector) document, so the directory walk lands in
-- padding and macro detection silently finds nothing. The sector shift is
-- validated against CFBF_MIN/MAX_SECTOR_SHIFT before this is ever called.
local function sector_offset(sec_id, sec_size)
  return (sec_id + 1) * sec_size + 1
end

local function get_fat_next(input, fat_sector_ids, entries_per_sector, sector_id)
  if sector_id == CFBF_ENDOFCHAIN or sector_id == CFBF_FREESECT then
    return nil
  end

  local fat_sector_index = math.floor(sector_id / entries_per_sector) + 1
  local fat_sector_id = fat_sector_ids[fat_sector_index]

  if not fat_sector_id then
    return nil
  end

  local entry_index = sector_id % entries_per_sector
  -- Four bytes per FAT entry, so entries_per_sector * 4 is the sector size
  local fat_offset = sector_offset(fat_sector_id, entries_per_sector * 4) +
      entry_index * 4

  return read_u32(input, fat_offset)
end

-- -------------------------------------------------------------------------
-- Main processing function
-- -------------------------------------------------------------------------

local function process_cfbf(input, mpart, task)
  if not input or #input < CFBF_MIN_SIZE then
    return nil
  end

  -- Validate CFBF magic before materialising anything: :sub() on an
  -- rspamd_text is a zero-copy span
  if tostring(input:sub(1, 8)) ~= CFBF_MAGIC then
    lua_util.debugm(N, task, 'cfbf: magic mismatch')
    return nil
  end

  -- The FAT and directory walks need random access at absolute offsets, so a
  -- bounded copy is materialised once here
  local buf = lua_content_util.to_string(input,
      lua_content_util.config.max_processing_size)
  local buf_len = #buf

  -- Parse header (all offsets 1-indexed in Lua)
  -- BOM at bytes 29-30: 0xFFFE = little-endian
  local bom = read_u16(buf, 29)

  if bom ~= CFBF_BOM_LE then
    lua_util.debugm(N, task, 'cfbf: unexpected byte order mark: %s', bom)
    return nil
  end

  -- Sector size power at bytes 31-32
  local sec_size_power = read_u16(buf, 31)

  if not sec_size_power or sec_size_power < CFBF_MIN_SECTOR_SHIFT
      or sec_size_power > CFBF_MAX_SECTOR_SHIFT then
    lua_util.debugm(N, task, 'cfbf: bad sector size power: %s', sec_size_power)
    return nil
  end

  -- bit.lshift keeps this an integer; 2^n yields a float, which is accepted
  -- as a string index only while it stays exactly integral
  local sec_size = bit.lshift(1, sec_size_power)
  local entries_per_sector = sec_size / 4

  -- FirstDirectorySectorID at bytes 0x31 (49) .. 0x34 (52), LE uint32
  local dir_sec_id = read_u32(buf, 49)

  if not dir_sec_id then
    lua_util.debugm(N, task, 'cfbf: could not read directory sector ID')
    return nil
  end

  local num_fat_sectors = read_u32(buf, 45)

  if not num_fat_sectors or num_fat_sectors == 0 then
    lua_util.debugm(N, task, 'cfbf: no FAT sectors')
    return nil
  end

  -- Header DIFAT holds the first 109 FAT-sector IDs. Any remaining IDs are
  -- held in a linked list of DIFAT sectors.
  local fat_sector_ids = {}
  local header_fat_count = math.min(num_fat_sectors, 109)

  for i = 0, header_fat_count - 1 do
    local fat_sector_id = read_u32(buf, 77 + i * 4)

    if not fat_sector_id or fat_sector_id == CFBF_FREESECT then
      break
    end

    fat_sector_ids[#fat_sector_ids + 1] = fat_sector_id
  end

  local difat_sec_id = read_u32(buf, 69)
  local num_difat_sectors = read_u32(buf, 73)
  local seen_difat_sectors = {}

  while #fat_sector_ids < num_fat_sectors
      and difat_sec_id and difat_sec_id ~= CFBF_ENDOFCHAIN
      and difat_sec_id ~= CFBF_FREESECT
      and not seen_difat_sectors[difat_sec_id]
      and num_difat_sectors > 0 do
    seen_difat_sectors[difat_sec_id] = true
    local difat_offset = sector_offset(difat_sec_id, sec_size)

    if difat_offset + sec_size - 1 > buf_len then
      break
    end

    for i = 0, entries_per_sector - 2 do
      if #fat_sector_ids >= num_fat_sectors then
        break
      end

      local fat_sector_id = read_u32(buf, difat_offset + i * 4)

      if not fat_sector_id or fat_sector_id == CFBF_FREESECT then
        break
      end

      fat_sector_ids[#fat_sector_ids + 1] = fat_sector_id
    end

    difat_sec_id = read_u32(buf, difat_offset + (entries_per_sector - 1) * 4)
    num_difat_sectors = num_difat_sectors - 1
  end

  if #fat_sector_ids == 0 then
    lua_util.debugm(N, task, 'cfbf: no usable header DIFAT entries')
    return nil
  end

  local result = {
    tag                = 'cfbf',
    doc_type           = nil,
    has_vba            = false,
    has_suspicious_vba = false,
    has_dde            = false,
    urls               = {},
    extract_text       = function(_specific)
      return nil
    end,
  }

  -- -----------------------------------------------------------------------
  -- Walk directory entries (each 128 bytes)
  -- Entry layout (MS-CFB §2.6):
  --   [0..63]   Directory entry name (UTF-16LE, up to 32 chars)
  --   [64..65]  Name length in bytes (uint16)
  --   [66]      Object type: 0=unused, 1=storage, 2=stream, 5=root
  --   [80..95]  CLSID (for storage entries)
  -- -----------------------------------------------------------------------
  local seen_sectors = {}
  local dir_sectors_walked = 0
  local debug_on = lua_content_util.debug_enabled()

  while dir_sec_id ~= CFBF_ENDOFCHAIN and dir_sec_id ~= CFBF_FREESECT
      and not seen_sectors[dir_sec_id]
      and dir_sectors_walked < CFBF_MAX_DIR_SECTORS do
    seen_sectors[dir_sec_id] = true
    dir_sectors_walked = dir_sectors_walked + 1
    local dir_offset = sector_offset(dir_sec_id, sec_size)

    if dir_offset + sec_size - 1 > buf_len then
      lua_util.debugm(N, task, 'cfbf: directory sector out of bounds')
      break
    end

    for entry_offset = dir_offset, dir_offset + sec_size - 128, 128 do
      local dtype = buf:byte(entry_offset + 66)

      if dtype == 1 or dtype == 2 or dtype == 5 then
        local name_len = read_u16(buf, entry_offset + 64)
        local name = name_len and decode_entry_name(buf, entry_offset, name_len)

        if name then
          if not result.has_vba and name_has_vba(name) then
            result.has_vba = true

            if debug_on then
              lua_util.debugm(N, task, 'cfbf: found VBA directory entry: %s', name)
            end
          end

          if not result.doc_type then
            local dtype_name = name_doc_type(name)

            if dtype_name then
              result.doc_type = dtype_name
              lua_util.debugm(N, task, 'cfbf: detected doc_type=%s', dtype_name)
            end
          end
        end
      end
    end

    local next_dir_sec_id = get_fat_next(buf, fat_sector_ids,
        entries_per_sector, dir_sec_id)

    if not next_dir_sec_id then
      lua_util.debugm(N, task, 'cfbf: cannot follow directory FAT chain')
      break
    end

    dir_sec_id = next_dir_sec_id
  end

  -- -----------------------------------------------------------------------
  -- DDE scan over the raw container bytes
  -- -----------------------------------------------------------------------
  lua_content_util.scan_flags(dde_trie, dde_patterns, buf, result)

  -- -----------------------------------------------------------------------
  -- Suspicious VBA keyword scan (only worthwhile when VBA is confirmed)
  -- Checks for auto-execution triggers + execution primitives that appear
  -- in plain ASCII in the p-code name tables without OVBA decompression.
  -- -----------------------------------------------------------------------
  if result.has_vba then
    local vba_hits = {}
    lua_content_util.scan_flags(vba_trie, vba_patterns, buf, vba_hits)

    if vba_hits.autoexec and vba_hits.exec then
      result.has_suspicious_vba = true
      lua_util.debugm(N, task,
          'cfbf: suspicious VBA — auto-exec trigger + execution primitive found')
    end
  end

  lua_util.debugm(N, task,
      'cfbf: result tag=%s doc_type=%s has_vba=%s has_suspicious_vba=%s has_dde=%s',
      result.tag, tostring(result.doc_type), result.has_vba,
      result.has_suspicious_vba, result.has_dde)

  lua_content_util.extract_urls(buf, mpart, task, result, 'cfbf')

  return result
end

--[[[
-- @function cfbf.process(input, mpart, task)
-- Processes a CFBF (OLE2) file: detects VBA macro presence via directory
-- entry name scanning, identifies document type, and checks for DDE fields
-- and suspicious auto-execution patterns.
--
-- Returns a table with fields:
--   tag              'cfbf'
--   doc_type         'word' | 'excel' | 'ppt' | 'msg' | nil
--   has_vba          true if VBA storage/stream found in directory
--   has_suspicious_vba  true if auto-exec + execution primitive in p-code area
--   has_dde          true if DDE/DDEAUTO field marker found
--   urls             list of extracted URLs
--]]
exports.process = process_cfbf

return exports
