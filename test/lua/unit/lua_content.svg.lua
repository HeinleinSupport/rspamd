-- SVG attachment heuristics (lua_content/svg)

context("SVG attachment heuristics", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"
  local svg = require "lua_content/svg"

  local hdrs = "From: <>\nTo: <nobody@example.com>\nSubject: test\n"

  local function get_task()
    local _res, task = rspamd_task.load_from_string(hdrs .. "\n", rspamd_config)
    task:process_message()
    return task
  end

  test("clean SVG produces no flags", function()
    local task = get_task()
    local input = [[<svg xmlns="http://www.w3.org/2000/svg"><circle r="5"/></svg>]]
    local res = svg.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.tag, 'svg')
    assert_false(res.has_scripts)
    assert_false(res.has_foreign_objects)
    task:destroy()
  end)

  test("detects embedded script and dropper pattern via foreignObject", function()
    local task = get_task()
    local input = [[<svg xmlns="http://www.w3.org/2000/svg">
<foreignObject><script src="https://evil.example.com/x?u=abcDEF1234567890xyz"></script></foreignObject>
</svg>]]
    local res = svg.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_scripts)
    assert_true(res.has_script_dropper)
    assert_true(res.has_foreign_objects)
    task:destroy()
  end)

  test("detects event handlers and javascript: protocol", function()
    local task = get_task()
    local input = [[<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
<a href="javascript:alert(2)">x</a></svg>]]
    local res = svg.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_event_handlers)
    assert_true(res.has_js_protocol)
    task:destroy()
  end)

  test("decompresses SVGZ (gzip) payload transparently", function()
    local task = get_task()
    local svg_src = [[<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>]]
    local compressed = rspamd_util.gzip_compress(svg_src)
    assert_not_nil(compressed)
    local res = svg.process(tostring(compressed), nil, task)
    assert_not_nil(res)
    assert_true(res.has_event_handlers)
    task:destroy()
  end)

  test("extracts URLs from SVG", function()
    local task = get_task()
    local input = [[<svg xmlns="http://www.w3.org/2000/svg">
<a href="http://evil.example.com/phish">x</a></svg>]]
    local res = svg.process(input, nil, task)
    assert_not_nil(res)
    assert_true(#res.urls > 0, "expected at least one URL extracted")
    task:destroy()
  end)
end)
