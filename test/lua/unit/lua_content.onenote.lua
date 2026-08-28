-- OneNote (.one) embedded-payload heuristics (lua_content/onenote)

context("OneNote attachment heuristics", function()
  local rspamd_task = require "rspamd_task"
  local onenote = require "lua_content/onenote"

  local hdrs = "From: <>\nTo: <nobody@example.com>\nSubject: test\n"

  local ONENOTE_MAGIC = "\xE4\x52\x5C\x7B\x8C\xD8\xA7\x4D\xAE\xB1\x53\x78\xD0\x29\x96\xD3"
  local FDSO_GUID = "\xE7\x16\xE3\xBD\x65\x26\x11\x45\xA4\xC4\x8D\x4D\x0B\x7A\x9E\xAC"

  local function get_task()
    local _res, task = rspamd_task.load_from_string(hdrs .. "\n", rspamd_config)
    task:process_message()
    return task
  end

  local function u32le(n)
    return string.char(n % 256, math.floor(n / 256) % 256,
        math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
  end

  -- Build a synthetic FileDataStoreObject: GUID + cbLength(8 bytes LE, only
  -- low 4 used) + payload data.
  local function make_fdso(payload)
    return FDSO_GUID .. u32le(#payload) .. "\0\0\0\0" .. payload
  end

  test("non-OneNote input returns nil", function()
    local task = get_task()
    local res = onenote.process("just some bytes", nil, task)
    assert_nil(res)
    task:destroy()
  end)

  test("valid magic without embedded files", function()
    local task = get_task()
    local input = ONENOTE_MAGIC .. string.rep("\0", 64)
    local res = onenote.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.tag, 'onenote')
    assert_false(res.has_embedded_files)
    task:destroy()
  end)

  test("detects embedded PE executable", function()
    local task = get_task()
    local payload = "MZ" .. string.rep("\x90", 64)
    local input = ONENOTE_MAGIC .. string.rep("\0", 16) .. make_fdso(payload)
    local res = onenote.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_embedded_files)
    assert_true(res.has_executable)
    task:destroy()
  end)

  test("detects embedded HTA/script dropper", function()
    local task = get_task()
    local payload = "<html><head><script>evil()</script></head></html>"
    local input = ONENOTE_MAGIC .. string.rep("\0", 16) .. make_fdso(payload)
    local res = onenote.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_embedded_files)
    assert_true(res.has_script)
    task:destroy()
  end)

  test("detects embedded OLE2 document", function()
    local task = get_task()
    local payload = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" .. string.rep("\0", 64)
    local input = ONENOTE_MAGIC .. string.rep("\0", 16) .. make_fdso(payload)
    local res = onenote.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_ole)
    task:destroy()
  end)

  test("does not scan beyond the declared embedded payload", function()
    local task = get_task()
    local input = ONENOTE_MAGIC .. make_fdso("x") .. "MZ" .. string.rep("\0", 64)
    local res = onenote.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_embedded_files)
    assert_false(res.has_executable)
    task:destroy()
  end)

  -- LUA_CONTENT_LIMIT states that content went uninspected, so a file holding
  -- exactly as many payloads as the cap allows must not raise it: every one of
  -- them was scanned.
  local function file_with_payloads(n)
    local parts = { ONENOTE_MAGIC }

    for i = 1, n do
      parts[#parts + 1] = make_fdso(string.format("payload %d", i))
    end

    return table.concat(parts)
  end

  test("a file at exactly the embedded-file cap is not reported as truncated", function()
    local task = get_task()
    local res = onenote.process(file_with_payloads(64), nil, task)

    assert_not_nil(res)
    assert_equal(#res.embedded_files, 64, 'all payloads must be found')
    local hits = require("lua_content").get_limits(task)
    assert_true(hits == nil or not hits['onenote:embedded_files'],
        'a fully scanned file must not claim content went uninspected')
    task:destroy()
  end)

  test("a file past the embedded-file cap is reported as truncated", function()
    local task = get_task()
    local res = onenote.process(file_with_payloads(65), nil, task)

    assert_not_nil(res)
    assert_equal(#res.embedded_files, 64, 'payloads must stop at the cap')
    assert_true(require("lua_content").get_limits(task)['onenote:embedded_files'],
        'a truncated file must be reported')
    task:destroy()
  end)

  test("extracts URLs from OneNote content", function()
    local task = get_task()
    local input = ONENOTE_MAGIC .. "http://evil.example.com/payload" .. string.rep("\0", 16)
    local res = onenote.process(input, nil, task)
    assert_not_nil(res)
    assert_true(#res.urls > 0, "expected at least one URL extracted")
    task:destroy()
  end)

  -- Regression: MZ, PK\3\4, #! and \x7FELF are magic bytes and only mean
  -- anything at offset 0 of the payload. Matched anywhere in the 512 byte
  -- header window, a two byte sequence like "MZ" hits arbitrary binary data
  -- roughly 1.5% of the time.
  test("MZ inside a payload body is not an executable", function()
    local task = get_task()
    -- A PNG-like payload whose body happens to contain the bytes "MZ"
    local payload = "\x89PNG\r\n\x1a\n" .. string.rep("\0", 40)
        .. "MZ" .. string.rep("\0", 40)
    local input = ONENOTE_MAGIC .. string.rep("\0", 64) .. make_fdso(payload)
    local res = onenote.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_embedded_files)
    assert_false(res.has_executable)
    task:destroy()
  end)

  test("shebang inside a payload body is not a script", function()
    local task = get_task()
    local payload = "\x89PNG\r\n\x1a\n" .. string.rep("\0", 30) .. "#!" .. string.rep("\0", 30)
    local input = ONENOTE_MAGIC .. string.rep("\0", 64) .. make_fdso(payload)
    local res = onenote.process(input, nil, task)
    assert_not_nil(res)
    assert_false(res.has_script)
    task:destroy()
  end)

  test("MZ at offset 0 of a payload is an executable", function()
    local task = get_task()
    local payload = "MZ" .. string.rep("\0", 80)
    local input = ONENOTE_MAGIC .. string.rep("\0", 64) .. make_fdso(payload)
    local res = onenote.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_executable)
    task:destroy()
  end)
end)
