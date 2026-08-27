-- CHM (Compiled HTML Help) heuristics (lua_content/chm)

context("CHM attachment heuristics", function()
  local rspamd_task = require "rspamd_task"
  local chm = require "lua_content/chm"

  local hdrs = "From: <>\nTo: <nobody@example.com>\nSubject: test\n"

  local function get_task()
    local _res, task = rspamd_task.load_from_string(hdrs .. "\n", rspamd_config)
    task:process_message()
    return task
  end

  local function u32le(n)
    return string.char(n % 256, math.floor(n / 256) % 256,
        math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
  end

  test("non-CHM input returns nil", function()
    local task = get_task()
    local res = chm.process("not a chm file", nil, task)
    assert_nil(res)
    task:destroy()
  end)

  test("recognizes valid ITSF v3 magic", function()
    local task = get_task()
    local input = "ITSF" .. u32le(3) .. string.rep("\0", 32)
    local res = chm.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.tag, 'chm')
    assert_equal(res.version, 3)
    task:destroy()
  end)

  test("rejects invalid ITSF version", function()
    local task = get_task()
    local input = "ITSF" .. u32le(99) .. string.rep("\0", 32)
    local res = chm.process(input, nil, task)
    assert_nil(res)
    task:destroy()
  end)
end)
