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
-- @module lua_content/hta
-- This module handles HTML Application (.hta) files.
-- HTA files are executed by Windows with full trust (mshta.exe) and have no
-- sandbox — the mere presence as an email attachment is suspicious.
-- Content analysis reuses the HTML heuristics module.
--]]

local html_module = require "lua_content/html"
local lua_util = require "lua_util"
local N = "lua_content"

local exports = {}

local function process_hta(input, mpart, task)
  if not input or #input == 0 then
    return nil
  end

  -- Reuse HTML processing — HTA is structurally HTML
  local result = html_module.process(input, mpart, task)

  if not result then
    result = {
      tag = 'hta',
      urls = {},
      extract_text = function(_specific) return nil end,
    }
  else
    -- Override tag so rules can distinguish HTA from plain HTML attachment
    result.tag = 'hta'
  end

  -- HTA files always carry elevated risk regardless of content
  result.is_hta = true
  lua_util.debugm(N, task, 'hta: file processed (always suspicious)')

  return result
end

--[[[
-- @function hta.process(input, mpart, task)
-- Processes an HTA file. Returns the same flags as html.process() plus:
--   is_hta = true  (always set — presence of an HTA attachment is itself a signal)
-- tag is set to 'hta' to allow rules to distinguish from HTML.
--]]
exports.process = process_hta

return exports
