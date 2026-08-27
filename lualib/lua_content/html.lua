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
-- @module lua_content/html
-- This module contains heuristics for HTML attachments.
-- HTML files sent as attachments (not as text/html body parts) are a common
-- phishing vector. This module extracts URLs and detects suspicious constructs.
--]]

local lua_content_util = require "lua_content/util"
local lua_util = require "lua_util"
local N = "lua_content"

local exports = {}

-- Suspicious HTML constructs, compiled into a single trie at module load time.
-- The order of this list defines the trie pattern indexes, so entries may be
-- appended but not reordered independently of it.
local html_patterns = {
  -- Inline script elements
  { 'has_scripts',        [=[(?i)<script[\s>]]=] },
  -- External script dropper with ?u=<token> parameter.
  -- This matches the widespread campaign pattern seen in HTML invoice spam:
  --   <script src="https://compromised-site.example/?u=<23-char-base62-token>">
  { 'has_script_dropper', [=[(?i)<script[^>]+src=["'][^"']+\?u=[a-zA-Z0-9]{10,}["']]=] },
  -- javascript: protocol in attribute values
  { 'has_js_protocol',    [=[(?i)javascript\s*:]=] },
  -- Meta refresh redirect: <meta http-equiv="refresh" ...>
  { 'has_meta_refresh',   [=[(?i)<meta[^>]+http-equiv\s*=\s*["']?refresh]=] },
  -- Form elements (potential credential harvesting)
  { 'has_forms',          [=[(?i)<form[\s>]]=] },
  -- Inline event handlers (onclick, onload, etc.)
  { 'has_event_handlers', [=[(?i)\s+on[a-z]+\s*=]=] },
  -- Hidden iframes
  { 'has_hidden_iframes', [=[(?i)<iframe[^>]+(?:width\s*=\s*["']?0|height\s*=\s*["']?0|display\s*:\s*none)]=] },
  -- Base tag that rewrites relative URLs
  { 'has_base_tag',       [=[(?i)<base[\s][^>]*href\s*=]=] },
}

local html_trie = lua_content_util.compile_flag_patterns(html_patterns)

--[[[
-- @function html.scan_flags(input, result)
-- Applies the HTML construct patterns to `input`, setting the corresponding
-- has_* flags on `result`. Exposed so that formats which are structurally
-- HTML (HTA, MHTML) can share the same single-pass scan.
--]]
local function scan_html_flags(input, result)
  lua_content_util.scan_flags(html_trie, html_patterns, input, result)
end

exports.scan_flags = scan_html_flags

local function process_html(input, mpart, task)
  if not input or #input == 0 then
    return nil
  end

  -- Kept as rspamd_text: the trie reads it in place, and only URL extraction
  -- needs (a bounded prefix of) it as a Lua string
  local scan_buf = lua_content_util.limit(input,
      lua_content_util.config.max_processing_size)

  local result = {
    tag = 'html',
    has_scripts = false,
    has_script_dropper = false,
    has_js_protocol = false,
    has_meta_refresh = false,
    has_forms = false,
    has_event_handlers = false,
    has_hidden_iframes = false,
    has_base_tag = false,
    urls = {},
    extract_text = function(_specific)
      return nil -- HTML text extraction handled by rspamd's built-in HTML parser
    end,
  }

  scan_html_flags(scan_buf, result)

  lua_util.debugm(N, task,
      'html: scripts=%s dropper=%s js=%s meta_refresh=%s forms=%s ' ..
      'events=%s hidden_iframe=%s base=%s',
      result.has_scripts, result.has_script_dropper, result.has_js_protocol,
      result.has_meta_refresh, result.has_forms, result.has_event_handlers,
      result.has_hidden_iframes, result.has_base_tag)

  -- Extract URLs from the HTML content, inject them into the task and store
  -- them in result.urls for rule access via part:get_specific()
  lua_content_util.extract_urls(input, mpart, task, result, 'html')

  return result
end

--[[[
-- @function html.process(input, mpart, task)
-- Processes an HTML attachment: detects suspicious constructs and extracts URLs.
-- Returns a table with boolean flags:
--   has_scripts, has_script_dropper, has_js_protocol, has_meta_refresh,
--   has_forms, has_event_handlers, has_hidden_iframes, has_base_tag
--
-- has_script_dropper specifically detects the widespread invoice-spam campaign
-- pattern: <script src="URL/?u=<token>"> used to load external dropper payloads.
--]]
exports.process = process_html

return exports
