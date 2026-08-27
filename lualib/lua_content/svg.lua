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
-- @module lua_content/svg
-- This module contains heuristics for SVG files
-- SVG files can embed scripts, event handlers and external references
-- making them a vector for phishing and malware delivery.
--]]

local rspamd_util = require "rspamd_util"
local lua_content_util = require "lua_content/util"
local lua_util = require "lua_util"
local N = "lua_content"

local exports = {}

-- Suspicious SVG constructs, compiled into a single trie at module load time.
-- The order of this list defines the trie pattern indexes, so entries may be
-- appended but not reordered independently of it.
local svg_patterns = {
  -- Script elements
  { 'has_scripts',          [=[(?i)<script[\s>]]=] },
  -- External script dropper with ?u=<token> parameter.
  -- Same campaign infrastructure as seen in HTML invoice spam,
  -- delivered via SVG <foreignObject> wrappers.
  { 'has_script_dropper',   [=[(?i)<script[^>]+src=["'][^"']+\?u=[a-zA-Z0-9]{10,}["']]=] },
  -- Inline event handler attributes (onclick, onload, onmouseover, etc.)
  { 'has_event_handlers',   [=[(?i)\s+on[a-z]+\s*=]=] },
  -- foreignObject can embed arbitrary HTML
  { 'has_foreign_objects',  [=[(?i)<foreignObject[\s>]]=] },
  -- <use> with external (non-fragment-only) href — SVG injection vector
  { 'has_external_use',     [=[(?i)<use[\s][^>]*(?:href|xlink:href)\s*=\s*["'][^#][^"']*["']]=] },
  -- javascript: protocol in any attribute value
  { 'has_js_protocol',      [=[(?i)javascript\s*:]=] },
  -- data: URIs (may carry malicious payloads in image-like context)
  { 'has_data_uri',         [=[(?i)["']data:[^/][^"']*["']]=] },
}

local svg_trie = lua_content_util.compile_flag_patterns(svg_patterns)

local function process_svg(input, mpart, task)
  if not input or #input == 0 then
    return nil
  end

  -- SVGZ files are gzip-compressed SVG; decompress before processing.
  -- Gzip magic: 0x1f 0x8b. Checked via :byte() so an uncompressed SVG never
  -- gets copied out of the rspamd_text just to look at two bytes.
  local b1, b2 = input:byte(1, 2)

  if b1 == 0x1f and b2 == 0x8b then
    lua_util.debugm(N, task, 'svg: detected gzip magic, decompressing as SVGZ')
    -- Bound the decompressed result: a small SVGZ can expand without limit
    local decompressed = rspamd_util.gzip_decompress(input,
        lua_content_util.config.max_processing_size)

    if not decompressed then
      lua_util.debugm(N, task, 'svg: failed to decompress SVGZ data')
      return nil
    end

    input = decompressed
  end

  -- Kept as rspamd_text: the trie reads it in place
  local scan_buf = lua_content_util.limit(input,
      lua_content_util.config.max_processing_size)

  local result = {
    tag = 'svg',
    has_scripts = false,
    has_script_dropper = false,
    has_event_handlers = false,
    has_foreign_objects = false,
    has_external_use = false,
    has_js_protocol = false,
    has_data_uri = false,
    urls = {},
    extract_text = function(_specific)
      return nil -- SVG text extraction not implemented
    end,
  }

  lua_content_util.scan_flags(svg_trie, svg_patterns, scan_buf, result)

  lua_util.debugm(N, task,
      'svg: scripts=%s dropper=%s events=%s foreign_object=%s ' ..
      'external_use=%s js=%s data_uri=%s',
      result.has_scripts, result.has_script_dropper, result.has_event_handlers,
      result.has_foreign_objects, result.has_external_use,
      result.has_js_protocol, result.has_data_uri)

  -- Extract URLs from the SVG content, inject them into the task and store
  -- them in result.urls for rule access via part:get_specific()
  lua_content_util.extract_urls(input, mpart, task, result, 'svg')

  return result
end

--[[[
-- @function svg.process(input, mpart, task)
-- Processes an SVG file: detects suspicious constructs and extracts URLs.
-- Returns a table with boolean flags:
--   has_scripts, has_script_dropper, has_event_handlers, has_foreign_objects,
--   has_external_use, has_js_protocol, has_data_uri
--
-- has_script_dropper specifically detects the widespread invoice-spam campaign
-- pattern seen in SVG-wrapped droppers: <script src="URL/?u=<token>"> embedded
-- inside <foreignObject> elements.
--]]
exports.process = process_svg

return exports
