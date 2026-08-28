-- Cost boundaries for the lua_content pre-analyzer (lua_content/util, init)
--
-- Every handler runs synchronously on the scan path, so what matters is not
-- only that a single part is bounded but that a message full of them is too.
-- These pin both halves.

context("lua_content cost boundaries", function()
  local rspamd_task = require "rspamd_task"
  local lua_content = require "lua_content"
  local lua_content_util = require "lua_content/util"

  local function get_task(msg)
    local _res, task = rspamd_task.load_from_string(
        msg or "From: <>\nTo: <nobody@example.com>\nSubject: test\n\n",
        rspamd_config)
    task:process_message()
    return task
  end

  -- Restores whatever the config held, so a failing test cannot leak a
  -- tightened limit into the rest of the suite. The assertion is re-raised
  -- rather than checked here: telescope injects its assert_* helpers into the
  -- test body's environment only, so a helper cannot call them.
  local function with_config(overrides, body)
    local cfg = lua_content_util.config
    local saved = {}

    for k, v in pairs(overrides) do
      saved[k] = cfg[k]
      cfg[k] = v
    end

    local ok, err = pcall(body)

    for k, v in pairs(saved) do
      cfg[k] = v
    end

    if not ok then
      error(err, 0)
    end
  end

  local function ical_of(nprops)
    return "BEGIN:VCALENDAR\r\n" ..
        string.rep("A:1\r\n", nprops) .. "END:VCALENDAR\r\n"
  end

  -- A byte limit does not bound a cost that is charged per property. 4 MB of
  -- five-byte properties is 800k of them, and one Lua table each used to mean
  -- a quarter of a gigabyte of heap, held for the whole task because
  -- set_specific() keeps a registry reference to the result.
  test("the element cap bounds a property-dense calendar", function()
    local ical = require "lua_content/ical"

    with_config({ max_elements = 50 }, function()
      local task = get_task()
      local res = ical.process(ical_of(5000), nil, task)

      assert_not_nil(res)
      assert_equal(#res.elts, 50, 'elements must stop at the cap')
      task:destroy()
    end)
  end)

  test("the element cap bounds a property-dense vcard", function()
    local vcard = require "lua_content/vcard"

    with_config({ max_elements = 50 }, function()
      local task = get_task()
      local res = vcard.process(
          "BEGIN:VCARD\r\nVERSION:3.0\r\n" ..
          string.rep("A:1\r\n", 5000) .. "END:VCARD\r\n", nil, task)

      assert_not_nil(res)
      assert_equal(#res.elts, 50, 'elements must stop at the cap')
      task:destroy()
    end)
  end)

  -- A conforming invite must be nowhere near the cap. BEGIN:VCALENDAR and
  -- END:VCALENDAR are properties like any other, so they count too.
  test("a normal invite is unaffected by the element cap", function()
    local ical = require "lua_content/ical"
    local task = get_task()
    local res = ical.process(ical_of(20), nil, task)

    assert_not_nil(res)
    assert_equal(#res.elts, 22)
    task:destroy()
  end)

  test("per-module processing size overrides the shared default", function()
    local cfg = lua_content_util.config

    assert_equal(lua_content_util.limit_for('ical'),
        cfg.max_processing_size_by_module.ical)
    assert_equal(lua_content_util.limit_for('svg'), cfg.max_processing_size)
  end)

  -- The per-part caps bound one attachment; without a cumulative budget a
  -- message simply pays them once per part and the total is unbounded.
  -- Admission has to cover the part it is admitting. Testing only what was
  -- already spent let a task at 12 MB take on a 4 MB part under a 16 MB
  -- budget and finish at 20 MB, so the budget bounded nothing by up to one
  -- whole attachment.
  test("the cumulative byte budget stops further parts", function()
    with_config({ max_total_bytes = 100, max_total_time = 1e9 }, function()
      local task = get_task()

      assert_true(lua_content_util.budget_check(task, 60), 'first part admitted')

      local ok, limit = lua_content_util.budget_check(task, 60)
      assert_false(ok, 'a part that would overshoot must be refused')
      assert_equal(limit, 'bytes')

      assert_true(lua_content_util.budget_check(task, 40),
          'a part that still fits must be admitted')
      task:destroy()
    end)
  end)

  test("the byte budget is never overshot", function()
    with_config({ max_total_bytes = 100, max_total_time = 1e9 }, function()
      local task = get_task()
      local admitted = 0

      for _ = 1, 20 do
        if lua_content_util.budget_check(task, 30) then
          admitted = admitted + 30
        end
      end

      assert_equal(admitted, 90, 'admitted bytes must stay within the budget')
      task:destroy()
    end)
  end)

  -- A first part larger than the whole budget used to be admitted
  -- unconditionally, because there was no state to compare it against yet.
  test("the first part is subject to the budget like any other", function()
    with_config({ max_total_bytes = 100, max_processing_size = 1024,
                  max_total_time = 1e9 }, function()
      local task = get_task()
      local ok, limit = lua_content_util.budget_check(task, 500)

      assert_false(ok, 'an oversized first part must be refused')
      assert_equal(limit, 'bytes')
      task:destroy()
    end)
  end)

  -- No handler reads more than its processing limit, so charging the raw part
  -- size would refuse a 20 MB PDF of which 32 KB is ever looked at.
  test("a part is charged what it can cost, not what it weighs", function()
    with_config({ max_total_bytes = 100, max_processing_size = 10,
                  max_total_time = 1e9 }, function()
      local task = get_task()

      for i = 1, 10 do
        assert_true(lua_content_util.budget_check(task, 1000000),
            'huge part ' .. i .. ' is charged only its processing limit')
      end

      assert_false(lua_content_util.budget_check(task, 1000000),
          'the eleventh exhausts the budget')
      task:destroy()
    end)
  end)

  test("the cumulative time budget stops further parts", function()
    with_config({ max_total_bytes = 1e12, max_total_time = -1 }, function()
      local task = get_task()

      -- The first call only starts the clock, so it is always admitted
      assert_true(lua_content_util.budget_check(task, 1), 'first part admitted')

      local ok, limit = lua_content_util.budget_check(task, 1)
      assert_false(ok, 'second part must be refused')
      assert_equal(limit, 'time')
      task:destroy()
    end)
  end)

  -- No handler reads more than *its own* limit, and iCal and vCard read
  -- 256 KB where the shared default is 4 MB. Charging them the default spent
  -- the whole budget on a handful of parts that between them inspected a
  -- fraction of it, skipping later handlers and raising LUA_CONTENT_BUDGET
  -- for nothing.
  test("a part is charged its own module's limit, not the shared default", function()
    with_config({ max_total_bytes = 4 * 1024 * 1024,
                  max_processing_size = 1024 * 1024,
                  max_processing_size_by_module = { ical = 256 * 1024 },
                  max_total_time = 1e9 }, function()
      local task = get_task()
      local admitted = 0

      for _ = 1, 100 do
        if lua_content_util.budget_check(task, 1024 * 1024, 'ical') then
          admitted = admitted + 1
        end
      end

      assert_equal(admitted, 16, 'ical must be charged 256 KB, not 1 MB')
      task:destroy()
    end)
  end)

  -- The dispatcher knows this module as 'vcf', the handler calls itself
  -- 'vcard'; the override must be found either way
  test("the module name the dispatcher uses resolves to the same limit", function()
    assert_equal(lua_content_util.limit_for('vcf'),
        lua_content_util.limit_for('vcard'))
    assert_equal(lua_content_util.limit_for(nil),
        lua_content_util.config.max_processing_size)
  end)

  -- budget_check only runs before a handler, so it can only notice an overrun
  -- when another recognised part follows. A message whose single content part
  -- was pathological used to overshoot in silence.
  test("an overrun is observed after the handler, not only before the next", function()
    with_config({ max_total_bytes = 1e12, max_total_time = -1 }, function()
      local task = get_task()

      assert_nil(lua_content_util.budget_observe(task),
          'nothing to observe before any part ran')

      assert_true(lua_content_util.budget_check(task, 1), 'first part admitted')
      assert_equal(lua_content_util.budget_observe(task), 'time',
          'the overrun must be visible without a following part')
      task:destroy()
    end)
  end)

  test("a handler within budget observes no overrun", function()
    with_config({ max_total_bytes = 1e12, max_total_time = 1e9 }, function()
      local task = get_task()

      lua_content_util.budget_check(task, 1)
      assert_nil(lua_content_util.budget_observe(task))
      task:destroy()
    end)
  end)

  test("the budget is per task, not global", function()
    with_config({ max_total_bytes = 100, max_total_time = 1e9 }, function()
      local t1 = get_task()
      assert_true(lua_content_util.budget_check(t1, 100), 'budget filled exactly')
      assert_false(lua_content_util.budget_check(t1, 1), 'first task is spent')

      local t2 = get_task()
      assert_true(lua_content_util.budget_check(t2, 1), 'second task starts fresh')

      t1:destroy()
      t2:destroy()
    end)
  end)

  -- Reported the same way a handler failure is: parts skipped for budget
  -- produce no symbols, which is indistinguishable from a clean scan.
  test("exhausting the budget is recorded on the task", function()
    local task = get_task()

    assert_nil(lua_content.get_budget_hit(task))
    lua_content.note_budget(task, 'bytes')
    assert_equal(lua_content.get_budget_hit(task), 'bytes')
    task:destroy()
  end)

  -- Every cap drops data silently, and a handler that stopped looking reports
  -- exactly like one that looked and found nothing. rules/content.lua turns
  -- these into LUA_CONTENT_LIMIT.
  test("the element cap is reported on the task", function()
    local ical = require "lua_content/ical"

    with_config({ max_elements = 50 }, function()
      local task = get_task()
      assert_nil(lua_content.get_limits(task))

      local res = ical.process(ical_of(5000), nil, task)

      assert_true(res.excessive_elements, 'result must flag the truncation')

      local hits = lua_content.get_limits(task)
      assert_not_nil(hits, 'the cap must be recorded')
      assert_true(hits['ical:elements'])
      task:destroy()
    end)
  end)

  test("a normal invite reports no limit at all", function()
    local ical = require "lua_content/ical"
    local task = get_task()
    local res = ical.process(ical_of(20), nil, task)

    assert_nil(res.excessive_elements)
    assert_nil(lua_content.get_limits(task))
    task:destroy()
  end)

  test("size truncation is reported", function()
    with_config({ max_processing_size_by_module = { probe = 16 } }, function()
      local task = get_task()

      local short = lua_content_util.bounded_string('0123456789', 'probe', task)
      assert_equal(#short, 10)
      assert_nil(lua_content.get_limits(task), 'a fitting part reports nothing')

      local long = lua_content_util.bounded_string(string.rep('x', 100), 'probe', task)
      assert_equal(#long, 16, 'content must be cut to the module limit')
      assert_true(lua_content.get_limits(task)['probe:size'])
      task:destroy()
    end)
  end)

  test("one hit is recorded once, however many parts reach it", function()
    with_config({ max_processing_size_by_module = { probe = 4 } }, function()
      local task = get_task()

      for _ = 1, 5 do
        lua_content_util.bounded_string(string.rep('x', 100), 'probe', task)
      end

      local n = 0
      for _ in pairs(lua_content.get_limits(task)) do n = n + 1 end
      assert_equal(n, 1, 'the same cap must not be reported per part')
      task:destroy()
    end)
  end)

  -- The URL cap used to stop URLs from being taken, but not the work: a
  -- handler calling the sink per property still paid for a string copy and a
  -- full rspamd_url.all() on every one of them long after the budget was out.
  test("an exhausted url sink refuses work before scanning", function()
    with_config({ max_urls = 2 }, function()
      local task = get_task()
      local result = { urls = {} }
      local sink = lua_content_util.make_url_sink(task, nil, result, 'test')

      assert_true(sink(nil), 'a fresh sink accepts work')

      for _ = 1, 10 do
        lua_content_util.extract_urls_into(sink,
            'see http://a.example.com/ and http://b.example.com/', task)
      end

      assert_equal(#result.urls, 2, 'url cap must hold')
      assert_false(sink(nil), 'a spent sink must refuse work up front')
      assert_true(lua_content.get_limits(task)['test:urls'],
          'the url cap must be reported like any other')
      task:destroy()
    end)
  end)
end)
