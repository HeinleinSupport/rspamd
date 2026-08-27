-- Virtual parts created through task:inject_part (lua_task.c)

context("Injected mime parts", function()
  local rspamd_task = require "rspamd_task"

  local hdrs = [[
From: <>
To: <nobody@example.com>
Subject: test
Content-Type: text/plain

Body.
]]

  -- Telescope injects its assertions into the test body's environment only,
  -- so helpers called from a test cannot use them
  local function get_task()
    local _res, task = rspamd_task.load_from_string(hdrs, rspamd_config)
    task:process_message()
    return task
  end

  local function injected_part(task)
    for _, p in ipairs(task:get_parts(true) or {}) do
      if p:is_injected() then
        return p
      end
    end

    return nil
  end

  test("an injected part is added as a virtual text part", function()
    local task = get_task()

    assert_true(task:inject_part('text', 'injected body text'))

    local p = injected_part(task)
    assert_not_nil(p, 'injected part must be reachable with include_virtual')

    -- and must stay out of the default view
    for _, q in ipairs(task:get_parts() or {}) do
      assert_false(q:is_injected(), 'virtual part leaked into the default part list')
    end

    task:destroy()
  end)

  -- A part is allocated with rspamd_mempool_alloc0, so an uninitialised cbref
  -- is 0 rather than -1. Registry ref 0 is the free list head and luaL_ref
  -- never hands it out, so treating it as a live reference makes is_specific()
  -- lie, makes get_specific() return the free list integer, and makes the
  -- message destructor unref slot 0 - which discards the free list head and
  -- leaks registry slots for the lifetime of the worker.
  test("an injected part carries no lua specific data", function()
    local task = get_task()

    assert_true(task:inject_part('text', 'injected body text'))

    local p = injected_part(task)
    assert_not_nil(p)
    assert_false(p:is_specific(), 'injected part must not claim specific data')
    assert_nil(p:get_specific(), 'injected part must not return a registry slot')

    task:destroy()
  end)

  test("specific data set on an injected part round trips", function()
    local task = get_task()

    assert_true(task:inject_part('text', 'injected body text'))

    local p = injected_part(task)
    assert_not_nil(p)

    p:set_specific({ tag = 'unit-test', value = 42 })
    assert_true(p:is_specific())

    local got = p:get_specific()
    assert_equal(type(got), 'table')
    assert_equal(got.tag, 'unit-test')
    assert_equal(got.value, 42)

    task:destroy()
  end)
end)
