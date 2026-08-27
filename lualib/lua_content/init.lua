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

--[[[
-- @module lua_content
-- This module contains content processing logic
--]]


local exports = {}
local N = "lua_content"
local lua_util = require "lua_util"
local logger = require "rspamd_logger"

-- Task cache key under which handler failures are recorded. rules/content.lua
-- reads it and raises LUA_CONTENT_ERROR, so that a detector dying mid-scan is
-- visible in the scan result rather than only in the log.
local failures_key = "lua_content_failures"

--[[[
-- @function lua_content.note_failure(task, module_name, err)
-- Records that `module_name` raised `err` while processing a part.
--]]
exports.note_failure = function(task, module_name, err)
  local failures = task:cache_get(failures_key)

  if not failures then
    failures = {}
    task:cache_set(failures_key, failures)
  end

  -- One entry per module: a message with many parts of the same broken type
  -- should report once, not once per part
  if not failures[module_name] then
    failures[module_name] = tostring(err)
  end
end

--[[[
-- @function lua_content.get_failures(task)
-- Returns { [module_name] = error_string } for handlers that failed, or nil.
--]]
exports.get_failures = function(task)
  return task:cache_get(failures_key)
end

local content_modules = {
  ical = {
    mime_type = { "text/calendar", "application/calendar" },
    module = require "lua_content/ical",
    extensions = { 'ics' },
    output = "text"
  },
  vcf = {
    mime_type = { "text/vcard", "application/vcard" },
    module = require "lua_content/vcard",
    extensions = { 'vcf' },
    output = "text"
  },
  pdf = {
    mime_type = "application/pdf",
    module = require "lua_content/pdf",
    extensions = { 'pdf' },
    output = "table"
  },
}

local modules_by_mime_type
local modules_by_extension

local function init()
  modules_by_mime_type = {}
  modules_by_extension = {}
  for k, v in pairs(content_modules) do
    if v.mime_type then
      if type(v.mime_type) == 'table' then
        for _, mt in ipairs(v.mime_type) do
          modules_by_mime_type[mt] = { k, v }
        end
      else
        modules_by_mime_type[v.mime_type] = { k, v }
      end

    end
    if v.extensions then
      for _, ext in ipairs(v.extensions) do
        modules_by_extension[ext] = { k, v }
      end
    end
  end
end

exports.maybe_process_mime_part = function(part, task)
  if not modules_by_mime_type then
    init()
  end

  local ctype, csubtype = part:get_type()
  local mt = string.format("%s/%s", ctype or 'application',
      csubtype or 'octet-stream')

  -- An inline text/html part is already parsed by rspamd's built-in HTML
  -- parser, so running the HTML heuristics over it again would duplicate that
  -- work; only process it when it arrives as an explicit attachment.
  --
  -- This deliberately does NOT extend to text/* as a whole. is_attachment()
  -- is false for any part without Content-Disposition: attachment and without
  -- a filename, which is exactly how every calendar client sends an invite
  -- (an inline text/calendar inside multipart/alternative) and how vCards
  -- arrive. Gating all of text/* would silently disable ical and vcf
  -- processing for the common case.
  if mt == 'text/html' and not part:is_attachment() then
    lua_util.debugm(N, task, "skip inline text/html part for content processing")
    return
  end

  local pair = modules_by_mime_type[mt]

  if not pair then
    local ext = part:get_detected_ext()

    if ext then
      pair = modules_by_extension[ext]
    end
  end

  if pair then
    lua_util.debugm(N, task, "found known content of type %s: %s",
        mt, pair[1])

    -- The content is passed through as an rspamd_text. Handlers must keep it
    -- that way for as long as they can: rspamd_regexp and rspamd_trie read a
    -- text in place, and :span()/:sub() over one are zero-copy views, so a
    -- multi-megabyte part never has to be duplicated into the Lua heap.
    -- See lua_content/util.lua for the shared size limits and helpers.
    --
    -- Called under pcall so that one handler cannot take the others with it.
    -- The C caller already invokes this function protected (message.c uses
    -- lua_pcall), so an unguarded error was never fatal - but it unwound out
    -- of here before part:set_specific() ran, which left the part looking
    -- exactly like one no handler had claimed. Every symbol for that content
    -- type then quietly stopped firing, with a single "cannot detect content"
    -- line in the rspamd log as the only evidence. Catching it here keeps the
    -- failure attributable to a module and lets it be reported as a symbol.
    local ok, data = pcall(pair[2].module.process, part:get_content(), part, task)

    if not ok then
      logger.errx(task, "lua_content handler %s failed on %s: %s",
          pair[1], mt, data)
      exports.note_failure(task, pair[1], data)

      return
    end

    if data then
      lua_util.debugm(N, task, "extracted content from %s: %s type",
          pair[1], type(data))
      part:set_specific(data)
    else
      lua_util.debugm(N, task, "failed to extract anything from %s",
          pair[1])
    end
  end

end

return exports