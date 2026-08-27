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
]] --

local l = require 'lpeg'
local lua_content_util = require "lua_content/util"
local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local N = "lua_content"

-- Valid VERSION values per RFC 6350 (4.0), RFC 2426 (3.0) and vCard 2.1.
-- Anything else (or absent) indicates a non-conforming producer -- same
-- rationale as ical.lua's PRODID/METHOD checks.
local valid_vcard_versions = lua_util.list_to_hash { '2.1', '3.0', '4.0' }

-- Properties whose value is legitimately binary and therefore legitimately
-- encoded. vCard 3.0 stores an inline photo as `PHOTO;ENCODING=b;TYPE=JPEG:`,
-- which is what most address books emit, so an encoded value on one of these
-- says nothing: neither decode it (the payload is not text, and it is often
-- hundreds of kilobytes) nor count it towards has_encoded_text.
local binary_value_keys = lua_util.list_to_hash {
  'photo',
  'logo',
  'sound',
  'key',
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
    -- covers ENCODING=b (vCard 3.0) and ENCODING=BASE64 (vCard 2.1)
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

local vcard_grammar

-- XXX: Currently it is a copy of ical grammar
local function gen_grammar()
  if not vcard_grammar then
    local wsp = l.S(" \t\v\f")
    local crlf = (l.P "\r" ^ -1 * l.P "\n") + l.P "\r"
    local eol = (crlf * #crlf) + (crlf - (crlf ^ -1 * wsp))
    local name = l.C((l.P(1) - (l.P ":")) ^ 1) / function(v)
      return (v:gsub("[\n\r]+%s", ""))
    end
    local value = l.C((l.P(1) - eol) ^ 0) / function(v)
      return (v:gsub("[\n\r]+%s", ""))
    end
    vcard_grammar = name * ":" * wsp ^ 0 * value * eol ^ -1
  end

  return vcard_grammar
end

local exports = {}

local function extract_text_data(specific)
  local fun = require "fun"

  local tbl = fun.totable(fun.map(function(e)
    return e[2]:lower()
  end, specific.elts))

  return table.concat(tbl, '\n')
end

local function process_vcard(input, mpart, task)
  local control = { n = '\n', r = '' }

  -- LPeg builds a capture table proportional to the input, so the same
  -- processing cap the attachment handlers use applies here too; without it a
  -- large synthetic file allocates without bound in the Lua heap.
  input = lua_content_util.to_string(input,
      lua_content_util.config.max_processing_size)

  -- One capped URL budget for the whole file. Injecting per property value
  -- without a shared cap lets a crafted file flood every downstream URL
  -- consumer.
  local urls = {}
  local url_sink = task and
      lua_content_util.make_url_sink(task, mpart, { urls = urls }, 'vcard') or nil
  local has_encoded_text = false
  local escaper = l.Ct((gen_grammar() / function(key, value)
    value = value:gsub("\\(.)", control)
    local raw_key = key:lower()
    key = raw_key

    -- A property may declare ENCODING=QUOTED-PRINTABLE or ENCODING=BASE64
    -- (e.g. `NOTE;ENCODING=QUOTED-PRINTABLE:...`). Decode before URL
    -- extraction: a real vCard viewer renders the decoded text, so a URL
    -- hidden behind the encoding would be visible to the recipient while
    -- staying invisible to rspamd_url.all() below.
    local base_key = raw_key:match('^([^;]+)') or raw_key
    local was_encoded
    value, was_encoded = maybe_decode_value(raw_key, base_key, value)

    if was_encoded then
      has_encoded_text = true
    end

    if url_sink then
      lua_content_util.extract_urls_into(url_sink, value, task)
    end
    lua_util.debugm(N, task, 'vcard: vcard key %s = "%s"',
        key, value)
    return { key, value }
  end) ^ 1)

  local elts = escaper:match(input)

  if not elts then
    return nil
  end

  -- -------------------------------------------------------------------------
  -- Structural spam signals
  -- -------------------------------------------------------------------------
  local has_version, version_value, has_fn = false, nil, false

  for _, elt in ipairs(elts) do
    local k, v = elt[1], elt[2]
    local base_key = k:match('^([^;]+)') or k

    if base_key == 'version' then
      has_version = true
      version_value = v:gsub('%s', '')
    elseif base_key == 'fn' then
      has_fn = true
    end
  end

  -- VERSION: absent or not a valid RFC 6350 / RFC 2426 / vCard 2.1 value
  local invalid_version = nil

  if not has_version then
    invalid_version = 'missing'
  elseif not valid_vcard_versions[version_value] then
    invalid_version = (version_value or ''):sub(1, 40)
  end

  return {
    tag = 'vcard',
    extract_text = extract_text_data,
    elts = elts,
    invalid_version = invalid_version,
    missing_fn = (not has_fn) or nil,
    has_encoded_text = has_encoded_text or nil,
    urls = urls,
  }
end

--[[[
-- @function vcard.process(input)
-- Returns all values from vcard as a plain text. Names are completely ignored.
--]]
exports.process = process_vcard

return exports
