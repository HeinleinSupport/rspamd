--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

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

local l = require 'lpeg'
local lua_content_util = require "lua_content/util"
local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local N = "lua_content"

-- ---------------------------------------------------------------------------
-- iCal spam-signal detection
-- ---------------------------------------------------------------------------

-- Valid METHOD values per RFC 5546 §3.2.
-- Anything else (e.g. "REPLAY" seen in the wild) is anomalous.
local valid_ical_methods = lua_util.list_to_hash {
  'publish', 'request', 'reply', 'add',
  'cancel', 'refresh', 'counter', 'declinecounter',
}

-- Zero-duration VALARM triggers that force an immediate notification popup.
-- Spammers use this to make calendar invites visually intrusive.
local immediate_triggers = lua_util.list_to_hash {
  '-pt0s', 'pt0s', 'p0d', '-p0d', 'pt0m', '-pt0m', 'pt0h', '-pt0h',
  'pt00s', '-pt00s',
}

-- Mainstream calendar servers that never adopted the RFC 5545 §3.7.3 FPI
-- format for PRODID; these are common in legitimate corporate meeting
-- invites, so their well-known prefixes are exempt from ICAL_INVALID_PRODID.
local known_nonconforming_prodid_prefixes = {
  'microsoft exchange server',
  'microsoft cdo for microsoft exchange',
  'microsoft cdo for windows 2000',
  'microsoft outlook',
}

local function is_known_nonconforming_prodid(prodid)
  local low = prodid:lower()
  for _, prefix in ipairs(known_nonconforming_prodid_prefixes) do
    if low:find(prefix, 1, true) == 1 then
      return true
    end
  end
  return false
end

-- NOTE: this module only *extracts* data (returned via part:set_specific()).
-- It deliberately does NOT call rspamd_config:register_symbol() / task:insert_result()
-- itself — same convention as pdf.lua/rtf.lua/etc. rspamd's C code only requires
-- "lua_content" (this module's parent, lua_content/init.lua) lazily, the first
-- time a MIME part actually needs content processing (rspamd_lua_require_function(L,
-- "lua_content", "maybe_process_mime_part") in libmime/message.c) — i.e. during
-- live task processing, well after config load / symcache init have finished, so
-- register_symbol() calls made from inside this module would never actually reach
-- cfg->symbols (rspamd_register_symbol_fromlua returns -1 once the symcache is past
-- its init phase), permanently disabling scoring and logging "unknown symbol X" from
-- lua_task_insert_result_common on every hit. The anomaly fields below (invalid_prodid,
-- invalid_method, numeric_location, immediate_alarm) are read and scored by
-- process_ical_specific() in rules/content.lua, which registers the
-- ICAL_INVALID_PRODID / ICAL_INVALID_METHOD / ICAL_NUMERIC_LOCATION / ICAL_IMMEDIATE_ALARM
-- virtual symbols at true top-level (content.lua is dofile'd eagerly, unlike this module).

local ical_grammar

local function gen_grammar()
  if not ical_grammar then
    local wsp = l.S(" \t\v\f")
    local crlf = (l.P "\r" ^ -1 * l.P "\n") + l.P "\r"
    local eol = (crlf * #crlf) + (crlf - (crlf ^ -1 * wsp))
    local name = l.C((l.P(1) - (l.P ":")) ^ 1) / function(v)
      return (v:gsub("[\n\r]+%s", ""))
    end
    local value = l.C((l.P(1) - eol) ^ 0) / function(v)
      return (v:gsub("[\n\r]+%s", ""))
    end
    ical_grammar = name * ":" * wsp ^ 0 * value * eol ^ -1
  end

  return ical_grammar
end

local exports = {}

local function extract_text_data(specific)
  local fun = require "fun"

  local tbl = fun.totable(fun.map(function(e)
    return e[2]:lower()
  end, specific.elts))
  return table.concat(tbl, '\n')
end


-- Properties whose value is legitimately binary and therefore legitimately
-- encoded. RFC 5545 3.1.3 defines ENCODING=BASE64 precisely for ATTACH, so an
-- encoded value on one of these says nothing at all: neither decode it (the
-- payload is not text and scanning it for URLs is wasted work on something
-- that can be megabytes) nor count it towards has_encoded_text.
local binary_value_keys = lua_util.list_to_hash {
  'attach',
  'image',
}

-- Upper bound on an encoded property value that is worth decoding
local max_decoded_value = 64 * 1024

-- Decode a QUOTED-PRINTABLE or BASE64 property value.
-- Returns decoded_value, was_encoded.
local function maybe_decode_value(raw_key, key, value)
  if binary_value_keys[key] then
    return value, false
  end

  if #value > max_decoded_value then
    return value, false
  end

  local decoded

  if raw_key:find(';encoding=quoted-printable', 1, true) then
    decoded = rspamd_util.decode_qp(value)
  elseif raw_key:find(';encoding=b', 1, true) then
    -- covers ENCODING=B (vCalendar 1.0) and ENCODING=BASE64 (RFC 5545)
    decoded = rspamd_util.decode_base64(value)
  else
    return value, false
  end

  if decoded then
    return tostring(decoded), true
  end

  -- Undecodable but explicitly declared as encoded: still an anomaly
  return value, true
end

-- Keys that can have visible urls
local url_keys = lua_util.list_to_hash {
  'description',
  'location',
  'summary',
  'organizer',
  'organiser',
  'attendee',
  'url'
}

local function process_ical(input, mpart, task)
  local control = { n = '\n', r = '' }

  -- LPeg builds a capture table proportional to the input, so the same
  -- processing cap the attachment handlers use applies here too; without it a
  -- large synthetic file allocates without bound in the Lua heap.
  -- limit_for() rather than the shared default: this parser costs per
  -- property, not per byte scanned, and a real invite is a few kilobytes.
  input = lua_content_util.bounded_string(input, 'ical', task)

  -- One capped URL budget for the whole file. Injecting per property value
  -- without a shared cap lets a crafted file flood every downstream URL
  -- consumer.
  local urls = {}
  local url_sink = task and
      lua_content_util.make_url_sink(task, mpart, { urls = urls }, 'ical') or nil
  local has_encoded_text = false
  -- Bytes don't bound a cost charged per property: 4 MB of 5-byte properties
  -- is 800k Lua tables held alive for the task. Past the cap, the capture
  -- returns nothing and the result table simply stops growing.
  local nelts = 0
  local truncated = false
  local max_elts = lua_content_util.config.max_elements
  local escaper = l.Ct((gen_grammar() / function(key, value)
    if nelts >= max_elts then
      if not truncated then
        truncated = true
        lua_content_util.note_limit(task, 'ical', 'elements')
      end

      return
    end

    nelts = nelts + 1
    value = value:gsub("\\(.)", control)
    local raw_key = key:lower()
    key = raw_key:match('^([^;]+)')

    -- A property may declare ENCODING=QUOTED-PRINTABLE or ENCODING=BASE64.
    -- Decode before URL extraction: a calendar client renders the decoded
    -- text, so a URL hidden behind the encoding would be visible to the
    -- recipient while staying invisible to rspamd_url.all() below.
    local was_encoded
    value, was_encoded = maybe_decode_value(raw_key, key or '', value)

    if was_encoded then
      has_encoded_text = true
    end

    if key and url_keys[key] and url_sink then
      lua_content_util.extract_urls_into(url_sink, value, task)
    end
    lua_util.debugm(N, task, 'ical: ical key %s = "%s"',
        key, value)
    return { key, value }
  end) ^ 1)

  local elts = escaper:match(input)

  if not elts then
    return nil
  end

  -- -------------------------------------------------------------------------
  -- Spam-signal detection over parsed elements
  -- -------------------------------------------------------------------------
  local prodid, has_prodid, method, location = nil, false, nil, nil
  local in_valarm   = false
  local alarm_trigger = nil

  for _, elt in ipairs(elts) do
    local k, v = elt[1], elt[2]
    if     k == 'prodid'      then prodid = v; has_prodid = true
    elseif k == 'method'      then method   = v:lower():gsub('%s', '')
    elseif k == 'location'    then location = v
    elseif k == 'begin'       then
      if v:lower() == 'valarm' then in_valarm = true end
    elseif k == 'end'         then
      if v:lower() == 'valarm' then in_valarm = false end
    elseif k == 'trigger' and in_valarm then
      alarm_trigger = v:lower():gsub('%s', '')
    end
  end

  -- PRODID: absent or not a valid RFC 5545 §3.7.3 Formal Public Identifier.
  -- All major calendar clients emit "-//Owner//Product//Language" or "+//...".
  -- A missing or free-form PRODID indicates a non-conforming (often spam) generator.
  local invalid_prodid = nil
  if not has_prodid then
    invalid_prodid = 'missing'
  elseif not (prodid:sub(1, 3) == '-//' or prodid:sub(1, 3) == '+//')
      and not is_known_nonconforming_prodid(prodid) then
    invalid_prodid = prodid:sub(1, 40)
  end

  -- METHOD: not a valid RFC 5546 value
  local invalid_method = nil
  if method and not valid_ical_methods[method] then
    invalid_method = method
  end

  -- LOCATION: exclusively numeric content (phone number, numeric group/room ID, etc.).
  -- A real-world location is an address or place name; pure digits indicate an ID.
  local numeric_location = nil
  if location then
    local loc = location:gsub('%s', '')
    if loc:match('^[%d%-%+%(%)]+$') then
      local digits = loc:gsub('[^%d]', '')
      if #digits >= 5 then
        numeric_location = loc
      end
    end
  end

  -- VALARM: zero-duration trigger forces immediate notification popup
  local immediate_alarm = nil
  if alarm_trigger and immediate_triggers[alarm_trigger] then
    immediate_alarm = alarm_trigger
  end

  return {
    tag = 'ical',
    extract_text = extract_text_data,
    elts = elts,
    -- More properties than real software ever emits, not just expensive to
    -- parse. Scored separately from the diagnostic LUA_CONTENT_LIMIT.
    excessive_elements = truncated or nil,
    invalid_prodid = invalid_prodid,
    invalid_method = invalid_method,
    numeric_location = numeric_location,
    immediate_alarm = immediate_alarm,
    has_encoded_text = has_encoded_text or nil,
    urls = urls,
  }
end

--[[[
-- @function lua_ical.process(input)
-- Returns all values from ical as a plain text. Names are completely ignored.
--]]
exports.process = process_ical

return exports