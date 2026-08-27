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

local lua_content = require "lua_content"

local function process_pdf_specific(task, part, specific)
  local suspicious_factor = 0
  if specific.encrypted then
    task:insert_result('PDF_ENCRYPTED', 1.0, part:get_filename() or 'unknown')
    suspicious_factor = suspicious_factor + 0.1
    if specific.openaction then
      suspicious_factor = suspicious_factor + 0.5
    end
  end

  if specific.scripts then
    task:insert_result('PDF_JAVASCRIPT', 1.0, part:get_filename() or 'unknown')
    suspicious_factor = suspicious_factor + 0.1
  end

  if specific.suspicious then
    suspicious_factor = suspicious_factor + specific.suspicious
  end

  if suspicious_factor > 0.5 then
    if suspicious_factor > 1.0 then
      suspicious_factor = 1.0
    end
    task:insert_result('PDF_SUSPICIOUS', suspicious_factor, part:get_filename() or 'unknown')
  end

  if specific.long_trailer then
    task:insert_result('PDF_LONG_TRAILER', 1.0, string.format('%s:%d',
        part:get_filename() or 'unknown', specific.long_trailer))
  end
  if specific.many_objects then
    task:insert_result('PDF_MANY_OBJECTS', 1.0, string.format('%s:%d',
        part:get_filename() or 'unknown', specific.many_objects))
  end
  if specific.timeout_processing then
    task:insert_result('PDF_TIMEOUT', 1.0, string.format('%s:%.3f',
        part:get_filename() or 'unknown', specific.timeout_processing))
  end
end

local function process_rtf_specific(task, part, specific)
  local fname = part:get_filename() or 'unknown'

  if specific.has_mz_in_hex then
    task:insert_result('RTF_EXECUTABLE_HEX', 1.0, fname)
  elseif specific.has_ole_object then
    task:insert_result('RTF_OBJECT', 1.0, fname)
  end

  if specific.has_dde then
    task:insert_result('RTF_DDE', 1.0, fname)
  end

  if specific.has_equation_exploit then
    task:insert_result('RTF_EQUATION_EXPLOIT', 1.0, fname)
  end

  if specific.has_staticdib_exploit then
    task:insert_result('RTF_STATICDIB_EXPLOIT', 1.0, fname)
  end

  if specific.has_level_obfuscation then
    task:insert_result('RTF_LEVEL_OBFUSCATION', 1.0, fname)
  end

  if specific.has_bin_keyword then
    task:insert_result('RTF_BINARY_DATA', 1.0, fname)
  end

  if specific.has_large_hex and not specific.has_mz_in_hex then
    task:insert_result('RTF_LARGE_HEX', 1.0, fname)
  end
end

local function process_hta_specific(task, part, specific)
  local fname = part:get_filename() or 'unknown'
  -- HTA presence is always suspicious; raise unconditionally
  task:insert_result('HTA_ATTACHMENT', 1.0, fname)

  if specific.has_script_dropper then
    task:insert_result('HTA_SCRIPT_DROPPER', 1.0, fname)
  end
end

local function process_onenote_specific(task, part, specific)
  local fname = part:get_filename() or 'unknown'

  if specific.has_executable then
    task:insert_result('ONENOTE_EXECUTABLE', 1.0, fname)
  end

  if specific.has_script then
    task:insert_result('ONENOTE_SCRIPT', 1.0, fname)
  end

  if specific.has_ole then
    task:insert_result('ONENOTE_OBJECT', 1.0, fname)
  end

  if specific.has_embedded_files and not specific.has_executable
      and not specific.has_script and not specific.has_ole then
    task:insert_result('ONENOTE_EMBEDDED', 1.0, string.format('%s:%d',
        fname, #specific.embedded_files))
  end
end

local function process_mhtml_specific(task, part, specific)
  local fname = part:get_filename() or 'unknown'

  if specific.has_password_input or specific.has_credential_fields then
    task:insert_result('MHTML_PHISHING', 1.0, fname)
  end

  if specific.has_scripts then
    task:insert_result('MHTML_SCRIPT', 1.0, fname)
  end

  if specific.has_meta_refresh then
    task:insert_result('MHTML_META_REFRESH', 1.0, fname)
  end
end

local function process_html_specific(task, part, specific)
  local fname = part:get_filename() or (function()
    local t, st = part:get_type()
    return string.format('inline:%s/%s', t or 'text', st or 'html')
  end)()

  if specific.has_script_dropper then
    task:insert_result('HTML_SCRIPT_DROPPER', 1.0, fname)
  elseif specific.has_scripts then
    task:insert_result('HTML_SCRIPT_ATTACH', 1.0, fname)
  end
end

local function process_svg_specific(task, part, specific)
  local fname = part:get_filename() or 'unknown'

  if specific.has_script_dropper then
    task:insert_result('SVG_SCRIPT_DROPPER', 1.0, fname)
  elseif specific.has_scripts then
    task:insert_result('SVG_SCRIPT', 1.0, fname)
  end

  if specific.has_foreign_objects then
    task:insert_result('SVG_FOREIGN_OBJECT', 1.0, fname)
  end
end

local function process_lnk_specific(task, part, specific)
  local fname = part:get_filename() or 'unknown'

  if specific.has_lolbin then
    task:insert_result('LNK_LOLBIN', 1.0, fname)
  end

  if specific.has_encoded_cmd then
    task:insert_result('LNK_ENCODED_CMD', 1.0, fname)
  elseif specific.has_suspicious_args then
    task:insert_result('LNK_SUSPICIOUS_ARGS', 1.0, fname)
  end

  if specific.has_icon_mismatch then
    task:insert_result('LNK_ICON_MISMATCH', 1.0, fname)
  end
end

local function process_cfbf_specific(task, part, specific)
  local fname = part:get_filename() or 'unknown'

  if specific.doc_type == 'msg' then
    task:insert_result('MSG_ATTACHMENT', 0.5, fname)
  end

  if specific.has_suspicious_vba then
    task:insert_result('CFBF_SUSPICIOUS_VBA', 1.0, fname)
  elseif specific.has_vba then
    task:insert_result('CFBF_VBA', 1.0, fname)
  end

  if specific.has_dde then
    task:insert_result('CFBF_DDE', 1.0, fname)
  end
end

local function process_ooxml_specific(task, part, specific)
  local fname = part:get_filename() or 'unknown'

  if specific.has_xlm_macros then
    task:insert_result('OOXML_XLM_MACROS', 1.0, fname)
  elseif specific.has_vbaproject then
    task:insert_result('OOXML_MACROS', 1.0, fname)
  elseif specific.has_macros_by_ext then
    task:insert_result('OOXML_MACROS_BY_EXT', 1.0, fname)
  end

  if specific.has_external_links then
    task:insert_result('OOXML_EXTERNAL_LINKS', 1.0, fname)
  end

  if specific.has_activex then
    task:insert_result('OOXML_ACTIVEX', 1.0, fname)
  end
end

local function process_chm_specific(task, part, _specific)
  local fname = part:get_filename() or 'unknown'
  task:insert_result('CHM_ATTACHMENT', 1.0, fname)
end

local function process_xml_specific(task, part, specific)
  local fname = part:get_filename() or 'unknown'

  -- XSLT presence signal (low score by itself)
  if specific.is_xslt then
    task:insert_result('XSLT_ATTACHMENT', 1.0, fname)
  end

  -- <msxsl:script> — almost always malicious
  if specific.has_msxsl_script then
    task:insert_result('XML_MSXSL_SCRIPT', 1.0, fname)
  end

  if specific.has_activex then
    task:insert_result('XML_ACTIVEX_DANGEROUS', 1.0, fname)
  end

  if specific.has_powershell then
    task:insert_result('XML_POWERSHELL_INVOCATION', 1.0, fname)
  end

  if specific.has_external_entity then
    task:insert_result('XML_EXTERNAL_ENTITY', 1.0, fname)
  end

  if specific.has_xinclude then
    task:insert_result('XML_XINCLUDE', 1.0, fname)
  end

  if specific.has_remote_document then
    task:insert_result('XML_REMOTE_DOCUMENT', 1.0, fname)
  end
end

-- Calendar invites and contact cards arrive inline inside multipart/alternative
-- far more often than as a named attachment (which is exactly why lua_content
-- does not gate them on is_attachment()), so a filename is usually absent and a
-- content-type label is the more useful identifier in the symbol option.
local function inline_label(part, default_subtype)
  local fname = part:get_filename()

  if fname then
    return fname
  end

  local t, st = part:get_type()

  return string.format('inline:%s/%s', t or 'text', st or default_subtype)
end

local function process_ical_specific(task, part, specific)
  local label = inline_label(part, 'calendar')

  if specific.invalid_prodid then
    task:insert_result('ICAL_INVALID_PRODID', 1.0,
        string.format('%s:%s', label, specific.invalid_prodid))
  end

  if specific.invalid_method then
    task:insert_result('ICAL_INVALID_METHOD', 1.0,
        string.format('%s:%s', label, specific.invalid_method))
  end

  if specific.numeric_location then
    -- Attacker-controlled and only length-bounded by the calendar value, so
    -- trim it the way ical.lua already trims PRODID before it reaches the log
    task:insert_result('ICAL_NUMERIC_LOCATION', 1.0,
        string.format('%s:%s', label, specific.numeric_location:sub(1, 40)))
  end

  if specific.immediate_alarm then
    task:insert_result('ICAL_IMMEDIATE_ALARM', 1.0,
        string.format('%s:%s', label, specific.immediate_alarm))
  end
end

local function process_vcard_specific(task, part, specific)
  local label = inline_label(part, 'vcard')

  if specific.invalid_version then
    task:insert_result('VCARD_INVALID_VERSION', 1.0,
        string.format('%s:%s', label, specific.invalid_version))
  end

  if specific.missing_fn then
    task:insert_result('VCARD_MISSING_FN', 1.0, label)
  end
end

local tags_processors = {
  pdf      = process_pdf_specific,
  rtf      = process_rtf_specific,
  hta      = process_hta_specific,
  onenote  = process_onenote_specific,
  mhtml    = process_mhtml_specific,
  html     = process_html_specific,
  svg      = process_svg_specific,
  lnk      = process_lnk_specific,
  cfbf     = process_cfbf_specific,
  ooxml    = process_ooxml_specific,
  chm      = process_chm_specific,
  xml      = process_xml_specific,
  ical     = process_ical_specific,
  vcard    = process_vcard_specific,
}

local function process_specific_cb(task)
  local parts = task:get_parts() or {}

  for _, p in ipairs(parts) do
    if p:is_specific() then
      local data = p:get_specific()

      if data and type(data) == 'table' and data.tag then
        if tags_processors[data.tag] then
          tags_processors[data.tag](task, p, data)
        end
      end
    end
  end

  -- A content handler that raised an error never reached set_specific(), so
  -- the loop above saw nothing for that part and every symbol of that content
  -- type is missing from this scan. Report it: without a symbol the only
  -- evidence is one line in the rspamd log, which is indistinguishable from
  -- routine noise and hides the fact that a detector is dead.
  local failures = lua_content.get_failures(task)

  if failures then
    for module_name, err in pairs(failures) do
      task:insert_result('LUA_CONTENT_ERROR', 1.0,
          string.format('%s: %s', module_name, err))
    end
  end
end

local id = rspamd_config:register_symbol {
  type = 'callback',
  name = 'SPECIFIC_CONTENT_CHECK',
  callback = process_specific_cb
}

rspamd_config:register_symbol {
  type = 'virtual',
  name = 'PDF_ENCRYPTED',
  parent = id,
  groups = { "content", "pdf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'PDF_JAVASCRIPT',
  parent = id,
  groups = { "content", "pdf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'PDF_SUSPICIOUS',
  parent = id,
  groups = { "content", "pdf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'PDF_LONG_TRAILER',
  parent = id,
  groups = { "content", "pdf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'PDF_MANY_OBJECTS',
  parent = id,
  groups = { "content", "pdf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'PDF_TIMEOUT',
  parent = id,
  groups = { "content", "pdf" },
}

-- RTF symbols
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'RTF_OBJECT',
  parent = id,
  score = 2.0,
  description = 'RTF file contains embedded OLE object',
  groups = { "content", "rtf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'RTF_EXECUTABLE_HEX',
  parent = id,
  score = 6.0,
  description = 'RTF file contains MZ (PE executable) magic in hex-encoded data',
  groups = { "content", "rtf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'RTF_DDE',
  parent = id,
  score = 4.0,
  description = 'RTF file contains DDE/DDEAUTO field (command execution on open)',
  groups = { "content", "rtf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'RTF_EQUATION_EXPLOIT',
  parent = id,
  score = 7.0,
  description = 'RTF file contains Equation Editor CLSID (CVE-2017-11882 family)',
  groups = { "content", "rtf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'RTF_LARGE_HEX',
  parent = id,
  score = 1.5,
  description = 'RTF file contains an unusually large hex-encoded block',
  groups = { "content", "rtf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'RTF_STATICDIB_EXPLOIT',
  parent = id,
  score = 8.0,
  description = 'RTF file contains malformed StaticDib OLE exploit indicator',
  groups = { "content", "rtf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'RTF_LEVEL_OBFUSCATION',
  parent = id,
  score = 2.0,
  description = 'RTF file uses suspicious list-level font obfuscation',
  groups = { "content", "rtf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'RTF_BINARY_DATA',
  parent = id,
  score = 1.0,
  description = 'RTF file contains an inline binary data block',
  groups = { "content", "rtf" },
}

-- HTA symbols
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'HTA_ATTACHMENT',
  parent = id,
  score = 5.0,
  description = 'HTML Application (.hta) attachment — executed with full trust by Windows',
  groups = { "content", "hta" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'HTA_SCRIPT_DROPPER',
  parent = id,
  score = 7.0,
  description = 'HTA attachment contains external script dropper (?u= pattern)',
  groups = { "content", "hta" },
}

-- OneNote symbols
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'ONENOTE_EXECUTABLE',
  parent = id,
  score = 8.0,
  description = 'OneNote file contains embedded PE/ELF executable payload',
  groups = { "content", "onenote" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'ONENOTE_SCRIPT',
  parent = id,
  score = 7.0,
  description = 'OneNote file contains embedded script payload (HTA/VBS/PS1/JS)',
  groups = { "content", "onenote" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'ONENOTE_OBJECT',
  parent = id,
  score = 3.0,
  description = 'OneNote file contains embedded OLE document',
  groups = { "content", "onenote" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'ONENOTE_EMBEDDED',
  parent = id,
  score = 1.5,
  description = 'OneNote file contains embedded file attachment(s)',
  groups = { "content", "onenote" },
}

-- MHTML symbols
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'MHTML_PHISHING',
  parent = id,
  score = 5.0,
  description = 'MHTML attachment contains credential harvesting form (password/login fields)',
  groups = { "content", "mhtml" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'MHTML_SCRIPT',
  parent = id,
  score = 3.0,
  description = 'MHTML attachment contains inline scripts',
  groups = { "content", "mhtml" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'MHTML_META_REFRESH',
  parent = id,
  score = 2.0,
  description = 'MHTML attachment uses meta refresh redirect',
  groups = { "content", "mhtml" },
}

-- HTML attachment symbols
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'HTML_SCRIPT_DROPPER',
  parent = id,
  score = 7.0,
  description = 'HTML attachment contains external script dropper (?u= campaign pattern)',
  groups = { "content", "html" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'HTML_SCRIPT_ATTACH',
  parent = id,
  score = 3.0,
  description = 'HTML attachment contains inline or external scripts',
  groups = { "content", "html" },
}

-- SVG symbols
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'SVG_SCRIPT_DROPPER',
  parent = id,
  score = 7.0,
  description = 'SVG attachment contains external script dropper (?u= campaign pattern)',
  groups = { "content", "svg" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'SVG_SCRIPT',
  parent = id,
  score = 4.0,
  description = 'SVG attachment contains embedded script',
  groups = { "content", "svg" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'SVG_FOREIGN_OBJECT',
  parent = id,
  score = 2.0,
  description = 'SVG attachment uses <foreignObject> to embed HTML content',
  groups = { "content", "svg" },
}

-- LNK symbols
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'LNK_LOLBIN',
  parent = id,
  score = 5.0,
  description = 'Windows Shortcut target or arguments invoke a LOLBin (living-off-the-land binary)',
  groups = { "content", "lnk" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'LNK_SUSPICIOUS_ARGS',
  parent = id,
  score = 4.0,
  description = 'Windows Shortcut has suspicious command-line arguments (download, IEX, obfuscation)',
  groups = { "content", "lnk" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'LNK_ENCODED_CMD',
  parent = id,
  score = 6.0,
  description = 'Windows Shortcut uses PowerShell -EncodedCommand (base64 payload)',
  groups = { "content", "lnk" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'LNK_ICON_MISMATCH',
  parent = id,
  score = 3.0,
  description = 'Windows Shortcut disguises itself with a document/image icon while targeting a script or LOLBin',
  groups = { "content", "lnk" },
}

-- CFBF (OLE2 legacy Office) symbols
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'CFBF_VBA',
  parent = id,
  score = 2.0,
  description = 'Legacy Office document (CFBF) contains VBA macro storage',
  groups = { "content", "cfbf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'CFBF_SUSPICIOUS_VBA',
  parent = id,
  score = 6.0,
  description = 'Legacy Office document has VBA with auto-execution trigger and execution primitive',
  groups = { "content", "cfbf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'CFBF_DDE',
  parent = id,
  score = 4.0,
  description = 'Legacy Office document contains DDE/DDEAUTO field (command execution on open)',
  groups = { "content", "cfbf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'MSG_ATTACHMENT',
  parent = id,
  score = 1.0,
  description = 'Outlook message (.msg) attachment — nested email; uncommon in legitimate mail, used for header-injection and phishing forwarding',
  groups = { "content", "cfbf" },
}

-- OOXML (Office Open XML) symbols
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'OOXML_MACROS',
  parent = id,
  score = 3.0,
  description = 'OOXML document contains a VBA macro project (vbaProject.bin)',
  groups = { "content", "ooxml" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'OOXML_XLM_MACROS',
  parent = id,
  score = 5.0,
  description = 'OOXML spreadsheet contains Excel 4.0 (XLM) macro sheets',
  groups = { "content", "ooxml" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'OOXML_EXTERNAL_LINKS',
  parent = id,
  score = 2.0,
  description = 'OOXML spreadsheet contains external data link references',
  groups = { "content", "ooxml" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'OOXML_ACTIVEX',
  parent = id,
  score = 2.0,
  description = 'OOXML document embeds ActiveX controls',
  groups = { "content", "ooxml" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'OOXML_MACROS_BY_EXT',
  parent = id,
  score = 1.5,
  description = 'OOXML file extension signals macro-enabled format (docm/xlsm/pptm) but no macro content confirmed',
  groups = { "content", "ooxml" },
}

-- CHM symbol
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'CHM_ATTACHMENT',
  parent = id,
  score = 8.0,
  description = 'Compiled HTML Help (CHM) attachment — hh.exe executes embedded HTML+Script without sandbox; almost never legitimate in email (active vector: Bumblebee, ValleyRAT)',
  groups = { "content", "chm" },
}

-- XML / XSLT symbols
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'XSLT_ATTACHMENT',
  parent = id,
  score = 1.5,
  description = 'XSLT stylesheet attachment (presence signal; escalated by scripting symbols)',
  groups = { "content", "xml" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'XML_MSXSL_SCRIPT',
  parent = id,
  score = 8.0,
  description = 'XML/XSLT contains <msxsl:script> (MSXML scripting extension; almost always malicious)',
  groups = { "content", "xml" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'XML_ACTIVEX_DANGEROUS',
  parent = id,
  score = 6.0,
  description = 'XML/XSLT contains dangerous ActiveX ProgID (WScript.Shell, ADODB.Stream, etc.)',
  groups = { "content", "xml" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'XML_POWERSHELL_INVOCATION',
  parent = id,
  score = 7.0,
  description = 'XML/XSLT contains PowerShell invocation pattern',
  groups = { "content", "xml" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'XML_EXTERNAL_ENTITY',
  parent = id,
  score = 2.0,
  description = 'XML document declares an external entity reference (XXE vector)',
  groups = { "content", "xml" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'XML_XINCLUDE',
  parent = id,
  score = 2.0,
  description = 'XML document uses XInclude namespace (server-side file inclusion vector)',
  groups = { "content", "xml" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'XML_REMOTE_DOCUMENT',
  parent = id,
  score = 3.0,
  description = 'XSLT document() function references a remote HTTP URL (data exfiltration / SSRF)',
  groups = { "content", "xml" },
}

-- iCal symbols. These are conformance signals on content that is otherwise
-- perfectly ordinary mail, so the scores stay low deliberately: a legitimate
-- but sloppy calendar generator must not be able to push a message over on
-- its own.
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'ICAL_INVALID_PRODID',
  parent = id,
  score = 1.0,
  description = 'iCalendar PRODID is missing or not an RFC 5545 formal public identifier',
  groups = { "content", "ical" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'ICAL_INVALID_METHOD',
  parent = id,
  score = 1.0,
  description = 'iCalendar METHOD is not one of the RFC 5546 values',
  groups = { "content", "ical" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'ICAL_NUMERIC_LOCATION',
  parent = id,
  score = 0.5,
  description = 'iCalendar LOCATION is purely numeric (phone number or numeric room id, not a place)',
  groups = { "content", "ical" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'ICAL_IMMEDIATE_ALARM',
  parent = id,
  score = 2.0,
  description = 'iCalendar VALARM has a zero-duration trigger, forcing an immediate notification popup',
  groups = { "content", "ical" },
}

-- vCard symbols
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'VCARD_INVALID_VERSION',
  parent = id,
  score = 1.0,
  description = 'vCard VERSION is missing or not a valid vCard 2.1 / RFC 2426 / RFC 6350 value',
  groups = { "content", "vcard" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'VCARD_MISSING_FN',
  parent = id,
  score = 0.5,
  description = 'vCard has no FN property, which every conforming version requires',
  groups = { "content", "vcard" },
}

-- Diagnostic symbol. Score 0: this says nothing about the message, only that
-- rspamd failed to inspect part of it, so it must never move a verdict.
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'LUA_CONTENT_ERROR',
  parent = id,
  score = 0.0,
  description = 'A lua_content handler raised an error, so the symbols for that content type could not be evaluated',
  groups = { "content" },
}
