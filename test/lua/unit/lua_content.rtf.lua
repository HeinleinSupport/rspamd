-- RTF heuristics (lua_content/rtf)

context("RTF content heuristics", function()
  local rspamd_task = require "rspamd_task"
  local rtf = require "lua_content/rtf"

  local hdrs = "From: <>\nTo: <nobody@example.com>\nSubject: test\n"

  local function get_task()
    local _res, task = rspamd_task.load_from_string(hdrs .. "\n", rspamd_config)
    task:process_message()
    return task
  end

  test("clean RTF produces no flags", function()
    local task = get_task()
    local input = [[{\rtf1\ansi\deff0 {\fonttbl{\f0 Times New Roman;}}
\f0\fs24 Hello, this is a plain RTF document with no macros.\par}]]
    local res = rtf.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.tag, 'rtf')
    assert_false(res.has_ole_object)
    assert_false(res.has_dde)
    assert_false(res.has_mz_in_hex)
    task:destroy()
  end)

  test("detects embedded OLE object", function()
    local task = get_task()
    local input = [[{\rtf1\ansi {\*\object\objemb\objdata 0105000002}}]]
    local res = rtf.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_ole_object)
    task:destroy()
  end)

  test("detects DDEAUTO field", function()
    local task = get_task()
    local input = [[{\rtf1\ansi {\field{\*\fldinst DDEAUTO c:\\windows\\system32\\cmd.exe "/c calc.exe" }}}]]
    local res = rtf.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_dde)
    task:destroy()
  end)

  test("detects MZ header hidden in hex payload", function()
    local task = get_task()
    local hex = "4d5a" .. string.rep("41", 20)
    local input = string.format([[{\rtf1\ansi {\*\objdata %s}}]], hex)
    local res = rtf.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_mz_in_hex)
    task:destroy()
  end)

  test("detects StaticDib CVE-2025-21298 fingerprint", function()
    local task = get_task()
    -- hex for ASCII "StaticDib"
    local staticdib_hex = "537461746963446962"
    local input = string.format([[{\rtf1\ansi {\*\objdata %s00000000}}]], staticdib_hex)
    local res = rtf.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_staticdib_exploit)
    task:destroy()
  end)

  test("detects inline binary data and list-level obfuscation", function()
    local task = get_task()
    local input = [[{\rtf1\ansi\bin4 data\leveltext\f1234}]]
    local res = rtf.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_bin_keyword)
    assert_true(res.has_level_obfuscation)
    task:destroy()
  end)

  test("extracts URLs from RTF text", function()
    local task = get_task()
    local input = [[{\rtf1\ansi\deff0 Visit http://evil.example.com/payload for more info.}]]
    local res = rtf.process(input, nil, task)
    assert_not_nil(res)
    assert_true(#res.urls > 0, "expected at least one URL extracted")
    task:destroy()
  end)

  -- Regression: \fldinst is the generic RTF field-instruction keyword and is
  -- present in every hyperlink, TOC entry, page number and mail-merge field.
  -- On its own it must never be reported as DDE.
  test("hyperlink field alone is not DDE", function()
    local task = get_task()
    local input = [[{\rtf1\ansi {\field{\*\fldinst HYPERLINK "http://example.com/" }{\fldrslt click}}}]]
    local res = rtf.process(input, nil, task)
    assert_not_nil(res)
    assert_false(res.has_dde)
    task:destroy()
  end)

  test("PAGE field alone is not DDE", function()
    local task = get_task()
    local input = [[{\rtf1\ansi {\field{\*\fldinst PAGE \\* MERGEFORMAT }}}]]
    local res = rtf.process(input, nil, task)
    assert_not_nil(res)
    assert_false(res.has_dde)
    task:destroy()
  end)

  -- Regression: "4d5a" occurs by chance roughly once per 64 KB of hex, so an
  -- unanchored search flags most documents carrying an ordinary embedded
  -- image. The MZ signature is only meaningful at the start of the object's
  -- hex stream.
  test("MZ appearing mid-hex is not an executable", function()
    local task = get_task()
    -- A picture blob whose bytes happen to contain the sequence 4d5a
    local hex = string.rep("41", 100) .. "4d5a" .. string.rep("42", 100)
    local input = string.format([[{\rtf1\ansi {\pict\wmetafile8 %s}}]], hex)
    local res = rtf.process(input, nil, task)
    assert_not_nil(res)
    assert_false(res.has_mz_in_hex)
    assert_true(res.has_large_hex)
    task:destroy()
  end)

  -- A real PE payload usually sits behind an OLE1 header, so its MZ magic is
  -- not at the start of \objdata. The DOS stub is what identifies it.
  test("detects hex-encoded PE DOS stub inside objdata", function()
    local task = get_task()
    -- OLE1 header bytes, then "MZ", then the hex-encoded DOS stub
    local hex = "0105000002000000" .. string.rep("00", 32) .. "4d5a"
        .. string.rep("41", 40)
        .. "546869732070726f6772616d2063616e6e6f742062652072756e"
    local input = string.format([[{\rtf1\ansi {\*\objdata %s}}]], hex)
    local res = rtf.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_mz_in_hex)
    task:destroy()
  end)

  test("detects raw PE DOS stub in a bin blob", function()
    local task = get_task()
    local input = [[{\rtf1\ansi\bin64 MZ....This program cannot be run in DOS mode....}]]
    local res = rtf.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_mz_in_hex)
    task:destroy()
  end)

  test("detects Equation Editor OLE class name", function()
    local task = get_task()
    local input = [[{\rtf1\ansi {\*\objclass Equation.3}{\*\objdata 0105000002}}]]
    local res = rtf.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_equation_exploit)
    task:destroy()
  end)

  test("detects hex-encoded Equation.3 class name in objdata", function()
    local task = get_task()
    -- "Equation.3" hex-encoded as it appears in the OLE1 header
    local input = [[{\rtf1\ansi {\*\objdata 01050000024571756174696f6e2e3300}}]]
    local res = rtf.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_equation_exploit)
    task:destroy()
  end)

  test("empty input returns nil", function()
    local task = get_task()
    local res = rtf.process("", nil, task)
    assert_nil(res)
    task:destroy()
  end)
end)
