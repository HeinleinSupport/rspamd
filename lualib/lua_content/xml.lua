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
-- @module lua_content/xml
-- This module inspects XML and XSLT attachments for malicious content patterns.
--
-- XSLT stylesheets are a recurring malware delivery vector because MSXML /
-- wscript.exe / mshta.exe will execute embedded <msxsl:script> blocks that
-- contain arbitrary JScript/VBScript.  Real-world payloads additionally use:
--   - ActiveX ProgIDs (WScript.Shell, ADODB.Stream, ...)
--   - PowerShell invocations embedded in script blocks
--   - External entity references and XInclude for data exfiltration
--   - XSLT document() calls to fetch remote payloads
--
-- Detection approach:
--   Scan the first + last 32 KB (bounded at 64 KB total) in a single trie
--   pass. All patterns are case-insensitive and are compiled once at module
--   load time. There are deliberately no plain-string prefilters in front of
--   the trie: Hyperscan already runs every pattern in one pass, and a
--   case-sensitive string.find() gate in front of a case-insensitive pattern
--   only creates a way to evade it.
--]]

local lua_content_util = require "lua_content/util"
local lua_util         = require "lua_util"
local N                = "lua_content"

local exports = {}

-- -------------------------------------------------------------------------
-- Pattern set (compiled into one trie at module load time)
-- The order of this list defines the trie pattern indexes, so entries may be
-- appended but not reordered independently of it.
-- -------------------------------------------------------------------------

local xml_patterns = {
  -- XSLT detection
  { 'is_xslt',             [=[(?i)xmlns:xsl\s*=\s*["']http://www\.w3\.org/\d{4}/XSL/Transform["']]=] },
  { 'is_xslt',             [=[(?i)<xsl:(?:stylesheet|transform)\b]=] },

  -- <msxsl:script> embedding (MSXML proprietary scripting extension)
  { 'has_msxsl_script',    [=[(?i)<msxsl:script\b]=] },

  -- language="JScript|VBScript|..." attribute on script elements
  { 'has_script_lang',     [=[(?i)\blanguage\s*=\s*["'](?:JScript|VBScript|C#|JavaScript)["']]=] },

  -- Dangerous ActiveX ProgIDs known to be used in XSLT-based malware
  { 'has_activex',         [=[(?i)ActiveXObject\s*\(\s*["'](?:WScript\.Shell|Shell\.Application|]=] ..
      [=[ADODB\.Stream|Scripting\.FileSystemObject|MSXML2\.XMLHTTP|]=] ..
      [=[MSXML2\.ServerXMLHTTP|WinHttp\.WinHttpRequest)["']]=] },

  -- PowerShell invocation patterns inside script blocks
  { 'has_powershell',      [=[(?i)\b(?:powershell(?:\.exe)?|pwsh)\b.{0,200}]=] ..
      [=[(?:-(?:EncodedCommand|enc\b|nop\b|noprofile\b|w\s+hidden|windowstyle\s+hidden)]=] ..
      [=[|IEX\b|Invoke-Expression\b|DownloadString\b|DownloadFile\b)]=] },

  -- XInclude namespace (server-side file inclusion)
  { 'has_xinclude',        [=[(?i)xmlns:xi\s*=\s*["']http://www\.w3\.org/2001/XInclude["']]=] },

  -- External entity declarations (XXE)
  { 'has_external_entity', [=[(?is)<!DOCTYPE[^>]+\[[^\]]*<!ENTITY[^>]+(?:SYSTEM|PUBLIC)\s+["']]=] },

  -- XSLT document() function with HTTP URL (remote payload fetch / SSRF)
  { 'has_remote_document', [=[(?i)\bdocument\s*\(\s*["']https?://]=] },
}

local xml_trie = lua_content_util.compile_flag_patterns(xml_patterns)

-- Long base64 blob (obfuscated payload). Kept out of the main trie because it
-- is only meaningful alongside another hit, so it is not worth the scan on the
-- overwhelming majority of parts that hit nothing at all.
local b64_patterns = {
  { 'has_long_b64', [=[[A-Za-z0-9+/]{200,}={0,2}]=] },
}

local b64_trie = lua_content_util.compile_flag_patterns(b64_patterns)

-- Bytes taken from each end of a large document. Malicious script blocks
-- appear early; encoded payloads may be appended at the end.
local XML_WINDOW = 32768

-- -------------------------------------------------------------------------
-- Main processing function
-- -------------------------------------------------------------------------

local function process_xml(input, mpart, task)
  -- Note: this check must precede any tostring(), because tostring(nil)
  -- yields the string "nil" and would make the guard unreachable
  if not input or #input == 0 then
    return nil
  end

  -- Quick reject: must look like XML (an opening tag near the start).
  -- Avoids wasting time on binary or plaintext false-positives.
  -- 0x3c is '<'; :byte() clamps to the available length on both a Lua string
  -- and an rspamd_text, and returns no table to allocate
  local b1, b2, b3, b4, b5, b6, b7, b8 = input:byte(1, 8)

  if b1 ~= 0x3c and b2 ~= 0x3c and b3 ~= 0x3c and b4 ~= 0x3c
      and b5 ~= 0x3c and b6 ~= 0x3c and b7 ~= 0x3c and b8 ~= 0x3c then
    lua_util.debugm(N, task, 'xml: quick reject — no XML opening')
    return nil
  end

  local result = {
    tag                 = 'xml',
    is_xslt             = false,
    has_msxsl_script    = false,
    has_script_lang     = false,
    has_activex         = false,
    has_powershell      = false,
    has_xinclude        = false,
    has_external_entity = false,
    has_remote_document = false,
    has_long_b64        = false,
    urls                = {},
    extract_text        = function(_specific)
      return nil
    end,
  }

  -- Scan the head and (for large documents) the tail as two separate spans,
  -- rather than concatenating them into a new 64 KB buffer
  local size = #input
  local head, tail

  if size > XML_WINDOW * 2 then
    head = lua_content_util.limit(input, XML_WINDOW)

    if type(input) == 'string' then
      tail = input:sub(size - XML_WINDOW + 1, size)
    else
      tail = input:span(size - XML_WINDOW + 1, XML_WINDOW)
    end
  else
    head = input
  end

  lua_content_util.scan_flags(xml_trie, xml_patterns, head, result)

  if tail then
    lua_content_util.scan_flags(xml_trie, xml_patterns, tail, result)
  end

  -- -----------------------------------------------------------------------
  -- Obfuscation indicator (only meaningful alongside other hits)
  -- -----------------------------------------------------------------------
  local any_hit = result.has_msxsl_script or result.has_script_lang
      or result.has_activex or result.has_powershell
      or result.has_external_entity or result.has_xinclude
      or result.has_remote_document

  if any_hit then
    lua_content_util.scan_flags(b64_trie, b64_patterns, head, result)

    if tail and not result.has_long_b64 then
      lua_content_util.scan_flags(b64_trie, b64_patterns, tail, result)
    end
  end

  lua_util.debugm(N, task,
      'xml: is_xslt=%s msxsl=%s script_lang=%s activex=%s ps=%s ' ..
      'xinclude=%s ext_entity=%s remote_doc=%s b64=%s',
      result.is_xslt, result.has_msxsl_script, result.has_script_lang,
      result.has_activex, result.has_powershell,
      result.has_xinclude, result.has_external_entity,
      result.has_remote_document, result.has_long_b64)

  lua_content_util.extract_urls(input, mpart, task, result, 'xml')

  return result
end

--[[[
-- @function xml.process(input, mpart, task)
-- Scans an XML or XSLT attachment for malicious content patterns.
--
-- Returns a table with boolean flags:
--   is_xslt             true if the document is an XSLT stylesheet
--   has_msxsl_script    <msxsl:script> element found
--   has_script_lang     language="JScript|VBScript|..." attribute found
--   has_activex         dangerous ActiveX ProgID referenced
--   has_powershell      PowerShell invocation pattern found
--   has_xinclude        XInclude namespace declared
--   has_external_entity DOCTYPE with external ENTITY declaration
--   has_remote_document XSLT document() call with HTTP URL
--   has_long_b64        long base64 blob alongside other suspicious content
--]]
exports.process = process_xml

return exports
