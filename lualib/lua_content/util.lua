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
]] --

--[[[
-- @module lua_content/util
-- Shared helpers for the lua_content format handlers.
--
-- Every handler runs synchronously on the scan path, once per matching MIME
-- part, so all of them follow the same two rules:
--
--   1. Never materialise a part as a Lua string unless an API demands one.
--      rspamd_regexp:match() and rspamd_trie:match() both accept rspamd_text
--      directly and read it in place; rspamd_url.all() does not (it uses
--      luaL_checklstring) and is the only reason a copy is ever made.
--   2. Never inspect more bytes than `config.max_processing_size`.
--
-- Handlers accept either an rspamd_text (the live path, via
-- mime_part:get_content()) or a plain Lua string (unit tests), so the helpers
-- here are type-preserving: give them a string and they hand back a string.
--]]

local rspamd_url = require "rspamd_url"
local rspamd_trie = require "rspamd_trie"
local bit = require "bit"
local lua_util = require "lua_util"

local N = "lua_content"
local exports = {}

exports.config = {
  -- Upper bound on the bytes any handler inspects. Larger parts are scanned
  -- up to this limit only. Format signatures and payload markers live near
  -- the start of a file, so a prefix scan loses very little in practice.
  max_processing_size = 4 * 1024 * 1024,
  -- Upper bound on the bytes handed to rspamd_url.all(). Deliberately much
  -- smaller than max_processing_size: this is the one call that forces a
  -- Lua string copy of the content.
  max_urls_scan_size = 512 * 1024,
  -- Upper bound on URLs injected into the task from a single part. Without
  -- it a crafted attachment can flood every URL-consuming module downstream.
  max_urls = 200,
}

-- Regexp tries are always compiled binary-safe: `dot_all` so that '.' spans
-- newlines in binary containers, `no_start` because only the fact of a match
-- matters here, never where it started.
local trie_flags = bit.bor(rspamd_trie.flags.re,
    rspamd_trie.flags.dot_all,
    rspamd_trie.flags.no_start)

--[[[
-- @function util.compile_flag_patterns(patterns)
-- Compiles an ordered { { flag_name, regexp }, ... } list into a single
-- Hyperscan trie.
--
-- One trie scan replaces one full pass over the content per pattern, and
-- since Hyperscan is a non-backtracking automaton the unbounded quantifiers
-- these patterns rely on (`[^>]+`, `[^"']+`) cannot degrade on adversarial
-- input the way the equivalent sequence of PCRE searches would.
--]]
function exports.compile_flag_patterns(patterns)
  local strs = {}

  for i, entry in ipairs(patterns) do
    strs[i] = entry[2]
  end

  return rspamd_trie.create(strs, trie_flags)
end

--[[[
-- @function util.scan_flags(trie, patterns, input, result)
-- Runs `trie` over `input` and sets `result[flag_name] = true` for every
-- pattern of `patterns` that matched. `input` may be an rspamd_text; it is
-- read in place, without a copy.
--]]
function exports.scan_flags(trie, patterns, input, result)
  local matches = trie:match(input)

  if not matches then
    return
  end

  for idx in pairs(matches) do
    local entry = patterns[idx]

    if entry then
      result[entry[1]] = true
    end
  end
end

--[[[
-- @function util.debug_enabled()
-- True when debug logging is active for this module.
--
-- Resolved through lua_util rather than called directly, because
-- lua_util.is_debug_enabled() was introduced together with this module. A
-- deployment that overlays lualib/lua_content/ onto an installed rspamd
-- without also replacing lualib/lua_util.lua would otherwise call a nil
-- field, and the resulting error unwinds out of maybe_process_mime_part
-- before part:set_specific() runs - which silently disables every symbol for
-- that content type, leaving nothing behind but one line in the rspamd log.
-- Losing the debug-guard optimisation on an old lua_util is a much better
-- outcome than losing the detector.
--]]
function exports.debug_enabled()
  local f = lua_util.is_debug_enabled

  if not f then
    return false
  end

  return f(N)
end

--[[[
-- @function util.limit(input, max_len)
-- Returns a view of `input` at most `max_len` bytes long, plus its length.
-- The type is preserved: an rspamd_text stays an rspamd_text, and `:span()`
-- is a zero-copy view rather than a duplicate of the bytes.
--]]
local function limit_input(input, max_len)
  local len = #input

  if len <= max_len then
    return input, len
  end

  if type(input) == 'string' then
    return input:sub(1, max_len), max_len
  end

  return input:span(1, max_len), max_len
end

exports.limit = limit_input

--[[[
-- @function util.to_string(input, max_len)
-- Materialises at most `max_len` bytes of `input` as a Lua string. Reserve
-- this for APIs that cannot consume an rspamd_text.
--]]
local function to_string(input, max_len)
  local bounded = limit_input(input, max_len or exports.config.max_processing_size)

  if type(bounded) == 'string' then
    return bounded
  end

  return tostring(bounded)
end

exports.to_string = to_string

--[[[
-- @function util.make_url_sink(task, mpart, result, tag)
-- Returns inject(url) -> boolean: it injects the URL into the task and
-- appends it to result.urls, returning false once config.max_urls have been
-- taken so the caller can stop early.
--
-- The cap lives in the sink rather than in each scan so that a handler which
-- looks at several buffers - MHTML decodes every inner part, iCal and vCard
-- see one property value at a time - shares one budget across all of them
-- instead of granting a fresh allowance per buffer.
--]]
function exports.make_url_sink(task, mpart, result, tag)
  local cfg = exports.config
  local debug_on = exports.debug_enabled()
  local urls = result.urls
  local n = 0

  return function(u)
    if n >= cfg.max_urls then
      return false
    end

    if debug_on then
      -- rspamd_url is a userdata the logger stringifies itself, so pass it
      -- through rather than calling tostring() on every URL unconditionally
      lua_util.debugm(N, task, '%s: found URL: %s', tag, u)
    end

    task:inject_url(u, mpart)
    urls[#urls + 1] = u
    n = n + 1

    return true
  end
end

--[[[
-- @function util.extract_urls_into(sink, input, task)
-- Finds URLs in a bounded prefix of `input` and feeds them to `sink`.
--]]
function exports.extract_urls_into(sink, input, task)
  local str = to_string(input, exports.config.max_urls_scan_size)

  if #str == 0 then
    return
  end

  local found = rspamd_url.all(task:get_mempool(), str)

  if not found then
    return
  end

  for _, u in ipairs(found) do
    if not sink(u) then
      break
    end
  end
end

--[[[
-- @function util.extract_urls(input, mpart, task, result, tag)
-- Finds URLs in a bounded prefix of `input`, injects them into the task and
-- appends them to `result.urls`, stopping at config.max_urls.
--]]
function exports.extract_urls(input, mpart, task, result, tag)
  if not task then
    -- Unit tests drive the handlers without a task
    return
  end

  exports.extract_urls_into(
      exports.make_url_sink(task, mpart, result, tag), input, task)
end

return exports
