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
local rspamd_util = require "rspamd_util"
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
  -- Upper bound on parsed elements (iCal/vCard properties). Byte limits alone
  -- don't bound a per-element cost: 4 MB of 5-byte properties is 800k Lua
  -- tables, kept alive for the task via set_specific(). A real card/invite
  -- has under a hundred properties, so this is generous by two orders of magnitude.
  max_elements = 10000,
  -- Per-format override of max_processing_size: right for a container scanned
  -- in one trie pass, wrong for a format parsed element by element (see
  -- max_elements).
  max_processing_size_by_module = {
    ical = 256 * 1024,
    vcard = 256 * 1024,
  },
  -- Cumulative budgets for one task, shared by every part of it. The per-part
  -- limits above bound a single attachment; without these, a message simply
  -- pays them once per part and the total is unbounded.
  max_total_time = 0.5,
  max_total_bytes = 16 * 1024 * 1024,
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

-- Every cap in this module set silently drops data: a truncated prefix, a
-- capped element list, a URL budget that ran out. Silence is indistinguishable
-- from "nothing found", so each one is recorded here and rules/content.lua
-- turns the set into LUA_CONTENT_LIMIT. Keyed by "module:limit" so a message
-- with many parts of the same type reports once rather than once per part.
local limits_key = "lua_content_limits"

--[[[
-- @function util.note_limit(task, module_name, limit)
-- Records that `module_name` hit `limit` ('size', 'elements', 'urls', ...).
--]]
function exports.note_limit(task, module_name, limit)
  if not task then
    -- Unit tests drive the handlers without a task
    return
  end

  local hits = task:cache_get(limits_key)

  if not hits then
    hits = {}
    task:cache_set(limits_key, hits)
  end

  hits[module_name .. ':' .. limit] = true
end

--[[[
-- @function util.get_limits(task)
-- Returns { ["module:limit"] = true } for the caps that were reached, or nil.
--]]
function exports.get_limits(task)
  return task:cache_get(limits_key)
end

-- The dispatcher knows a module by its content_modules key, a handler by the
-- name it passes to bounded_string(); the two differ for exactly one module.
-- Mapping here keeps that detail out of both.
local limit_aliases = {
  vcf = 'vcard',
}

--[[[
-- @function util.limit_for(module_name)
-- The processing size budget for one module: its override if it has one,
-- otherwise the shared default. A nil name yields the shared default.
--]]
function exports.limit_for(module_name)
  local cfg = exports.config
  local name = limit_aliases[module_name] or module_name

  return cfg.max_processing_size_by_module[name] or cfg.max_processing_size
end

--[[[
-- @function util.bounded_text(input, module_name, task)
-- The module's size-bounded view of `input`, reporting the truncation.
-- Prefer this over util.limit() wherever a task is in hand.
--]]
function exports.bounded_text(input, module_name, task)
  local max_len = exports.limit_for(module_name)

  if #input > max_len then
    exports.note_limit(task, module_name, 'size')
  end

  return limit_input(input, max_len)
end

--[[[
-- @function util.bounded_string(input, module_name, task)
-- As util.bounded_text, but materialised as a Lua string for the APIs that
-- cannot consume an rspamd_text.
--]]
function exports.bounded_string(input, module_name, task)
  local max_len = exports.limit_for(module_name)

  if #input > max_len then
    exports.note_limit(task, module_name, 'size')
  end

  return to_string(input, max_len)
end

--[[[
-- @function util.budget_check(task, nbytes, module_name)
-- Cumulative per-task admission control. Returns true when a part of
-- `nbytes` handled by `module_name` may still be processed, or false plus
-- the limit name ('bytes'/'time'). Per-part limits bound one attachment but
-- not a whole message: 1 MB calendar attachments in a 48 MB message once
-- cost 8s of synchronous CPU in one worker before this existed.
--
-- Both limits are kept: bytes catch many small parts, time catches one
-- pathological part - though only once it has run (see budget_observe()).
-- Timing starts on the first call, not task start, since this is about the
-- content handlers' own cost.
--]]
local budget_key = "lua_content_budget"

function exports.budget_check(task, nbytes, module_name)
  if not task then
    -- Unit tests drive the handlers without a task
    return true
  end

  local cfg = exports.config
  -- Charge what the part can actually cost, not its size: no handler reads
  -- past its own processing limit, and charging iCal/vCard (256 KB each) the
  -- shared 4 MB default would spend the whole budget on a few parts for nothing.
  local charge = math.min(nbytes, exports.limit_for(module_name))
  local st = task:cache_get(budget_key)
  local first = false

  if not st then
    -- Created even for a part that is then refused, so a task can't reset its
    -- clock/byte count by leading with one oversized part
    st = { started = rspamd_util.get_ticks(), spent = 0 }
    task:cache_set(budget_key, st)
    first = true
  end

  -- Must cover this part too, not just what was already spent, or a task at
  -- 12 MB could take a 4 MB part under a 16 MB budget and finish at 20 MB.
  if st.spent + charge > cfg.max_total_bytes then
    return false, 'bytes'
  end

  -- The clock starts here, so the first part cannot have overspent it
  if not first
      and rspamd_util.get_ticks() - st.started >= cfg.max_total_time then
    return false, 'time'
  end

  st.spent = st.spent + charge

  return true
end

--[[[
-- @function util.budget_observe(task)
-- Returns 'time' when this task has already spent its time budget, or nil.
-- budget_check() only notices an overrun before the *next* part, so a
-- message with one pathological content part would overshoot silently;
-- call this after the handler returns to catch that case too.
--]]
function exports.budget_observe(task)
  if not task then
    return nil
  end

  local st = task:cache_get(budget_key)

  if not st then
    return nil
  end

  if rspamd_util.get_ticks() - st.started >= exports.config.max_total_time then
    return 'time'
  end

  return nil
end

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

  -- Queried by extract_urls_into() up front, so a handler that calls the sink
  -- per property stops paying for a string copy + rspamd_url.all() once the
  -- cap is spent, instead of only being refused the result afterwards.
  local reported = false

  local function exhausted()
    if n < cfg.max_urls then
      return false
    end

    if not reported then
      reported = true
      exports.note_limit(task, tag, 'urls')
    end

    return true
  end

  return function(u)
    if u == nil then
      -- Budget probe rather than a URL
      return not exhausted()
    end

    if exhausted() then
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
  -- Ask before working: see make_url_sink()
  if not sink(nil) then
    return
  end

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
