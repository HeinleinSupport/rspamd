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
-- @module lua_content/mhtml
-- This module handles MHTML/MHT files (MIME HTML, RFC 2557).
-- MHTML is a single-file web archive: a multipart/related MIME message
-- containing the HTML and all its resources (images, CSS, scripts) encoded
-- inline (usually base64 or quoted-printable).
--
-- Used in phishing campaigns to deliver self-contained credential-harvesting
-- pages as a single attachment that renders fully in a browser or Outlook.
-- Also used to smuggle HTML dropper payloads since some gateways do not
-- inspect the inner MIME parts.
--
-- Strategy: confirm the multipart/related wrapper from the outer header block,
-- then split the archive on its MIME boundary and decode each inner text part
-- before applying the HTML heuristics to it.
--
-- Decoding is not optional. An MHT archive stores its HTML part however the
-- producer chose, and both of the usual choices defeat a raw scan:
--   * base64 leaves no HTML byte sequences at all;
--   * quoted-printable escapes '=' as '=3D', and every HTML attribute
--     contains '=', so `type="password"` is stored as `type=3D"password"`.
-- Quoted-printable is what browsers normally emit for text/html, so a scan of
-- the raw archive misses the common case, never mind a deliberate evasion.
--]]

local rspamd_regexp = require "rspamd_regexp"
local rspamd_util = require "rspamd_util"
local lua_content_util = require "lua_content/util"
local lua_util = require "lua_util"
local N = "lua_content"

local exports = {}

-- Upper bound on the outer header block. A MIME entity whose headers do not
-- end within this much data is not something worth treating as an archive.
local MHTML_HEADER_WINDOW = 8192

-- Wrapper detection: the *outer* Content-Type must be multipart/related.
--
-- Anchored to the start of a line so that neither a folded continuation line
-- nor the literal text of some other header value can stand in for a real
-- header. Anchoring alone is not enough though - see outer_header_block()
-- below, which is what stops an inner part header from being read as the
-- outer one.
--
-- The trailing group is a MIME token boundary: without it the pattern also
-- accepts a prefix of some other subtype, so "multipart/relatedness" would
-- register as an MHTML wrapper. A token ends at whitespace, a ';' parameter
-- list, a comment, end of line, or - since this runs against the isolated
-- header block - the end of that block.
local wrapper_patterns = {
  { 'is_mhtml', [=[(?i)(?:^|\n)Content-Type\s*:\s*multipart/related(?:[ \t;(\r\n]|$)]=] },
}

local wrapper_trie = lua_content_util.compile_flag_patterns(wrapper_patterns)

-- Return just the outer header block of a MIME entity: everything up to the
-- first empty line.
--
-- Scanning a flat window of the leading bytes instead would accept any
-- multipart/related found there, including one belonging to a *nested* part.
-- A forwarded message carrying an ordinary multipart/related section would
-- then be classified as an MHTML archive and scored with the phishing
-- heuristics below, which is a false positive on completely normal mail.
local function outer_header_block(input)
  local window, window_len = lua_content_util.limit(input, MHTML_HEADER_WINDOW)

  -- :find(needle, 1, true) is a plain search on a Lua string and on an
  -- rspamd_text alike, and with init = 1 the offset it reports is absolute
  local crlf = window:find('\r\n\r\n', 1, true)
  local lf = window:find('\n\n', 1, true)
  local header_end

  if crlf and lf then
    header_end = math.min(crlf, lf)
  else
    header_end = crlf or lf
  end

  if not header_end then
    -- No blank line within the window: not a well-formed MIME entity header
    return nil
  end

  local block = lua_content_util.limit(window, header_end - 1)

  return block, window_len
end

-- Inner parts examined per archive, and the total number of decoded bytes the
-- HTML heuristics are allowed to look at across all of them.
local MHTML_MAX_PARTS = 32
local MHTML_MAX_DECODED = 1024 * 1024

-- The boundary parameter of the outer Content-Type. A capture is needed, so
-- this is a regexp rather than a trie entry.
local boundary_re = rspamd_regexp.create_cached(
    [=[(?i)boundary\s*=\s*(?:"([^"]+)"|([^\s;"]+))]=])

-- True when byte offset `idx` starts a genuine MIME boundary delimiter line:
-- preceded by the start of the buffer or a newline, followed by an optional
-- closing "--", optional transport padding, then a newline/end of buffer.
-- Without this, "--boundary" occurring incidentally inside a part's own
-- (possibly encoded) content would be read as a delimiter and split the
-- archive in the wrong place.
--
-- RFC 2046 5.1.1 defines transport padding as *LWSP-char, with no upper
-- bound, so the padding run must not be capped: a producer - or an attacker -
-- may put arbitrarily many spaces before the CRLF, and refusing such a line
-- makes split_parts() return nothing at all. The inner parts then stay
-- undecoded and a base64 or quoted-printable phishing body becomes invisible,
-- which is precisely the evasion this validation exists to close.
--
-- Everything is therefore matched *in place*. string.find anchors '^' at its
-- init position and returns offsets rather than substrings, so no part of the
-- remaining archive is ever copied. That is what keeps this linear: the check
-- runs once per literal occurrence of the delimiter, and materialising the
-- tail with buf:sub() would make a body full of near-miss delimiter lines
-- copy megabytes per candidate and stall the worker synchronously. The
-- padding scans cannot compound either - each one stops at the first byte
-- that is not SP/TAB, so the scans of successive candidates partition the
-- buffer instead of overlapping.
local function is_boundary_line(buf, idx, delim_len)
  if idx > 1 and buf:sub(idx - 1, idx - 1) ~= '\n' then
    return false
  end

  local from = idx + delim_len

  -- Optional closing "--" of a terminating delimiter
  if buf:find('^%-%-', from) then
    from = from + 2
  end

  -- Consume the transport padding, however long it is
  local _, pad_end = buf:find('^[ \t]*', from)
  local nxt = pad_end + 1

  if nxt > #buf then
    -- The delimiter, with its padding, ends the archive
    return true
  end

  local c = buf:sub(nxt, nxt)

  return c == '\n' or (c == '\r' and buf:sub(nxt + 1, nxt + 1) == '\n')
end

-- The next genuine boundary delimiter line at or after `from`, or nil.
local function find_boundary(buf, from, delim)
  local pos = from

  while true do
    local idx = buf:find(delim, pos, true)

    if not idx then
      return nil
    end

    if is_boundary_line(buf, idx, #delim) then
      return idx
    end

    pos = idx + 1
  end
end

-- Split an archive body on its MIME boundary delimiter.
-- Returns the parts, and whether the cap cut the archive short. An archive of
-- exactly MHTML_MAX_PARTS parts is complete: only a part that actually follows
-- the cap means content went uninspected.
local function split_parts(buf, boundary)
  local parts = {}
  local delim = '--' .. boundary
  local first = find_boundary(buf, 1, delim)

  if not first then
    return parts, false
  end

  local pos = first + #delim

  while #parts < MHTML_MAX_PARTS do
    -- The closing delimiter is "--boundary--"
    if buf:sub(pos, pos + 1) == '--' then
      return parts, false
    end

    local nxt = find_boundary(buf, pos, delim)

    if not nxt then
      return parts, false
    end

    parts[#parts + 1] = buf:sub(pos, nxt - 1)
    pos = nxt + #delim
  end

  -- Stopped at the cap: truncated only if another part really follows
  return parts, buf:sub(pos, pos + 1) ~= '--'
      and find_boundary(buf, pos, delim) ~= nil
end

-- Split one inner part into its header block and body.
local function split_headers(part)
  local crlf = part:find('\r\n\r\n', 1, true)
  local lf = part:find('\n\n', 1, true)
  local at, skip

  if crlf and (not lf or crlf <= lf) then
    at, skip = crlf, 4
  elseif lf then
    at, skip = lf, 2
  else
    return nil
  end

  return part:sub(1, at - 1), part:sub(at + skip)
end

-- Removes RFC 5322 header folding (CRLF/LF immediately followed by SP/TAB)
-- entirely, rather than collapsing it to one space. A lenient MUA discards
-- the fold the same way when rendering, so a value - or even a header name -
-- deliberately split at a byte boundary (e.g. "text/\r\n html",
-- "Content-Transfer-\r\n Encoding") must reassemble into one token here too,
-- or the substring checks below are trivially evaded.
local function unfold(text)
  return (text:gsub('\r?\n[ \t]+', ''))
end

-- The value of the first `name:` header, scoped to just that logical line of
-- an already-unfolded header block (one physical line per header). Without
-- this, a plain substring search over the whole block can be hijacked by an
-- unrelated decoy header carrying the same text (e.g. an "X-Note:
-- boundary=decoy" header read as if it were part of Content-Type).
--
-- Linear whitespace between the field name and the colon is accepted on
-- purpose. The wrapper trie matches `Content-Type\s*:`, so refusing that
-- spelling here would let "Content-Type : multipart/related" register as an
-- MHTML archive and then yield no boundary at all - the inner parts would
-- never be decoded and the phishing heuristics would see only the raw,
-- still-encoded archive. The same spelling on an inner part's
-- Content-Transfer-Encoding would leave a base64 body undecoded.
local function header_line(header, name)
  local lname = name:lower()
  local nlen = #lname

  for line in (header .. '\n'):gmatch('([^\n]*)\n') do
    local lline = line:lower()

    -- Compared as a plain prefix rather than a Lua pattern: header names
    -- contain '-', which is a quantifier in a pattern
    if lline:sub(1, nlen) == lname and lline:sub(nlen + 1):match('^[ \t]*:') then
      return line
    end
  end

  return nil
end

-- Decode one inner part's body according to its Content-Transfer-Encoding.
-- Returns nil for parts that are not worth looking at as text.
local function decode_part(part, budget)
  local headers, body = split_headers(part)

  if not headers or not body or #body == 0 then
    return nil
  end

  headers = unfold(headers)

  -- Only text parts can carry the constructs the heuristics look for.
  -- A part with no Content-Type defaults to text/plain per RFC 2045.
  local ctype = header_line(headers, 'content-type')

  if ctype and not ctype:lower():find('content%-type%s*:%s*text/') then
    return nil
  end

  if #body > budget then
    body = body:sub(1, budget)
  end

  local cte = header_line(headers, 'content-transfer-encoding')
  local lcte = cte and cte:lower() or ''

  if lcte:find('base64', 1, true) then
    -- A truncated base64 body must still decode, so trim to a 4-char group
    local trimmed = body:gsub('%s', '')
    local usable = #trimmed - (#trimmed % 4)

    if usable <= 0 then
      return nil
    end

    local decoded = rspamd_util.decode_base64(trimmed:sub(1, usable))

    return decoded and tostring(decoded) or nil
  end

  if lcte:find('quoted-printable', 1, true) then
    local decoded = rspamd_util.decode_qp(body)

    return decoded and tostring(decoded) or nil
  end

  -- 7bit / 8bit / binary / absent: already plain text
  return body
end

-- Suspicious constructs inside the archive body. The order of this list
-- defines the trie pattern indexes, so entries may be appended but not
-- reordered independently of it.
local mhtml_patterns = {
  -- script tag inside a part
  { 'has_scripts',           [=[(?i)<script[\s>]]=] },
  -- meta refresh inside a part
  { 'has_meta_refresh',      [=[(?i)<meta[^>]+http-equiv\s*=\s*["']?refresh]=] },
  -- form element
  { 'has_forms',             [=[(?i)<form[\s>]]=] },
  -- javascript: in attribute values
  { 'has_js_protocol',       [=[(?i)javascript\s*:]=] },
  -- Password input — strong phishing indicator
  { 'has_password_input',    [=[(?i)<input[^>]+type\s*=\s*["']?password["']?]=] },
  -- Credential-related field names (login, email, username, passwd)
  { 'has_credential_fields', [=[(?i)<input[^>]+name\s*=\s*["']?(?:login|email|user(?:name)?|passwd?|password)["']?]=] },
}

local mhtml_trie = lua_content_util.compile_flag_patterns(mhtml_patterns)

local function process_mhtml(input, mpart, task)
  if not input or #input == 0 then
    return nil
  end

  -- Reject non-MHTML from the outer header block alone, without touching the
  -- body and without looking at any nested part's headers
  local header = outer_header_block(input)

  if not header then
    lua_util.debugm(N, task, 'mhtml: no outer header block found')
    return nil
  end

  -- Unfolded once and reused below for both wrapper detection and the
  -- boundary lookup, so a continuation-line fold cannot split a token out
  -- from under either check (see unfold()'s comment).
  header = unfold(lua_content_util.to_string(header, MHTML_HEADER_WINDOW))

  local wrapper = {}
  lua_content_util.scan_flags(wrapper_trie, wrapper_patterns, header, wrapper)

  if not wrapper.is_mhtml then
    lua_util.debugm(N, task, 'mhtml: outer Content-Type is not multipart/related')
    return nil
  end

  local result = {
    tag = 'mhtml',
    has_scripts = false,
    has_meta_refresh = false,
    has_forms = false,
    has_js_protocol = false,
    has_password_input = false,
    has_credential_fields = false,
    part_count = 0,
    urls = {},
    extract_text = function(_specific) return nil end,
  }

  -- The raw archive is still scanned: it catches 7bit/8bit inner parts and
  -- anything sitting in the MIME headers themselves, and it is the fallback
  -- when the boundary cannot be determined.
  local scan_buf = lua_content_util.limit(input,
      lua_content_util.config.max_processing_size)

  lua_content_util.scan_flags(mhtml_trie, mhtml_patterns, scan_buf, result)

  -- One URL budget shared by the raw archive and every decoded part
  local sink = task and
      lua_content_util.make_url_sink(task, mpart, result, 'mhtml') or nil

  if sink then
    lua_content_util.extract_urls_into(sink, scan_buf, task)
  end

  -- Decode the inner parts and scan those too. Without this the heuristics
  -- only ever see an archive whose HTML happens to be stored unencoded.
  -- Scoped to the outer Content-Type header's own line: searching the whole
  -- header block let an unrelated header carrying "boundary=" hijack the
  -- extracted value.
  local boundary
  local ctype = header_line(header, 'content-type')
  local bm = ctype and boundary_re:search(ctype, true, true)

  if bm and bm[1] then
    boundary = bm[1][2] or bm[1][3]
  end

  if boundary then
    local buf = lua_content_util.bounded_string(input, 'mhtml', task)
    local parts, parts_truncated = split_parts(buf, boundary)
    local budget = MHTML_MAX_DECODED

    result.part_count = #parts

    if parts_truncated then
      lua_content_util.note_limit(task, 'mhtml', 'parts')
    end

    for _, part in ipairs(parts) do
      if budget <= 0 then
        lua_content_util.note_limit(task, 'mhtml', 'decoded')
        break
      end

      local decoded = decode_part(part, budget)

      if decoded and #decoded > 0 then
        budget = budget - #decoded
        lua_content_util.scan_flags(mhtml_trie, mhtml_patterns, decoded, result)

        if sink then
          lua_content_util.extract_urls_into(sink, decoded, task)
        end
      end
    end
  else
    lua_util.debugm(N, task, 'mhtml: no boundary parameter, raw scan only')
  end

  lua_util.debugm(N, task,
      'mhtml: parts=%s scripts=%s meta_refresh=%s forms=%s js=%s password=%s creds=%s',
      result.part_count, result.has_scripts, result.has_meta_refresh,
      result.has_forms, result.has_js_protocol, result.has_password_input,
      result.has_credential_fields)

  return result
end

--[[[
-- @function mhtml.process(input, mpart, task)
-- Processes an MHTML/MHT file: detects phishing indicators and extracts URLs.
-- Returns a table with boolean flags:
--   has_scripts, has_meta_refresh, has_forms, has_js_protocol,
--   has_password_input, has_credential_fields
-- and:
--   part_count  - number of inner MIME parts examined
--   urls[]      - all URLs found in the document
--]]
exports.process = process_mhtml

return exports
