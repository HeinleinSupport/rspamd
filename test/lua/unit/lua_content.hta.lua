-- HTA attachment heuristics (lua_content/hta)

context("HTA attachment heuristics", function()
  local rspamd_task = require "rspamd_task"
  local hta = require "lua_content/hta"

  local hdrs = "From: <>\nTo: <nobody@example.com>\nSubject: test\n"

  local function get_task()
    local _res, task = rspamd_task.load_from_string(hdrs .. "\n", rspamd_config)
    task:process_message()
    return task
  end

  test("HTA is always flagged suspicious even with plain content", function()
    local task = get_task()
    local input = [[<html><body><p>Nothing suspicious here</p></body></html>]]
    local res = hta.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.tag, 'hta')
    assert_true(res.is_hta)
    task:destroy()
  end)

  test("HTA reuses html script dropper detection", function()
    local task = get_task()
    local input = [[<html><head>
<script src="https://compromised-site.example/?u=abcDEF1234567890xyz"></script>
</head></html>]]
    local res = hta.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_script_dropper)
    assert_true(res.is_hta)
    task:destroy()
  end)

  test("empty input returns nil", function()
    local task = get_task()
    local res = hta.process("", nil, task)
    assert_nil(res)
    task:destroy()
  end)
end)
