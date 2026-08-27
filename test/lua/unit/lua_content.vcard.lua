-- vCard heuristics (lua_content/vcard)

context("vCard content heuristics", function()
  local rspamd_task = require "rspamd_task"
  local vcard = require "lua_content/vcard"

  local hdrs = "From: <>\nTo: <nobody@example.com>\nSubject: test\n"

  local function get_task()
    local _res, task = rspamd_task.load_from_string(hdrs .. "\n", rspamd_config)
    task:process_message()
    return task
  end

  local function make_vcard(lines)
    local out = { "BEGIN:VCARD" }
    for _, l in ipairs(lines) do
      out[#out + 1] = l
    end
    out[#out + 1] = "END:VCARD"
    out[#out + 1] = ""
    return table.concat(out, "\r\n")
  end

  test("conforming vCard produces no structural flags", function()
    local task = get_task()
    local res = vcard.process(make_vcard {
      "VERSION:3.0",
      "FN:Jane Doe",
      "N:Doe;Jane;;;",
      "EMAIL:jane@example.com",
    }, nil, task)
    assert_not_nil(res)
    assert_equal(res.tag, 'vcard')
    assert_nil(res.invalid_version)
    assert_nil(res.missing_fn)
    assert_nil(res.has_encoded_text)
    task:destroy()
  end)

  test("detects missing VERSION", function()
    local task = get_task()
    local res = vcard.process(make_vcard {
      "FN:Jane Doe",
    }, nil, task)
    assert_not_nil(res)
    assert_equal(res.invalid_version, 'missing')
    task:destroy()
  end)

  test("detects a non-conforming VERSION value", function()
    local task = get_task()
    local res = vcard.process(make_vcard {
      "VERSION:9.9",
      "FN:Jane Doe",
    }, nil, task)
    assert_not_nil(res)
    assert_equal(res.invalid_version, '9.9')
    task:destroy()
  end)

  test("detects missing FN", function()
    local task = get_task()
    local res = vcard.process(make_vcard {
      "VERSION:3.0",
      "N:Doe;Jane;;;",
    }, nil, task)
    assert_not_nil(res)
    assert_true(res.missing_fn)
    task:destroy()
  end)

  -- A URL hidden behind quoted-printable renders normally in a vCard viewer,
  -- so it must be decoded before URL extraction runs.
  test("decodes quoted-printable text and extracts the hidden URL", function()
    local task = get_task()
    local res = vcard.process(make_vcard {
      "VERSION:3.0",
      "FN:Jane Doe",
      "NOTE;ENCODING=QUOTED-PRINTABLE:Visit =68=74=74=70=3A=2F=2Fevil=2Eexample=2Ecom=2Fpay",
    }, nil, task)
    assert_not_nil(res)
    assert_true(res.has_encoded_text)
    local found = false
    for _, u in ipairs(task:get_urls() or {}) do
      if tostring(u):find('evil.example.com', 1, true) then
        found = true
      end
    end
    assert_true(found, "expected the quoted-printable URL to be extracted")
    task:destroy()
  end)

  test("decodes base64 text", function()
    local task = get_task()
    -- base64 of "http://evil.example.com/b64"
    local res = vcard.process(make_vcard {
      "VERSION:3.0",
      "FN:Jane Doe",
      "NOTE;ENCODING=b:aHR0cDovL2V2aWwuZXhhbXBsZS5jb20vYjY0",
    }, nil, task)
    assert_not_nil(res)
    assert_true(res.has_encoded_text)
    task:destroy()
  end)

  -- Regression: vCard 3.0 stores an inline photo as PHOTO;ENCODING=b, which is
  -- what most address books emit. Treating that as an anomaly would fire on a
  -- large share of entirely ordinary contact cards.
  test("inline PHOTO with base64 encoding is not an anomaly", function()
    local task = get_task()
    local res = vcard.process(make_vcard {
      "VERSION:3.0",
      "FN:Jane Doe",
      "PHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQg=",
    }, nil, task)
    assert_not_nil(res)
    assert_nil(res.has_encoded_text)
    task:destroy()
  end)

  test("inline LOGO and KEY with base64 encoding are not anomalies", function()
    local task = get_task()
    local res = vcard.process(make_vcard {
      "VERSION:3.0",
      "FN:Jane Doe",
      "LOGO;ENCODING=b;TYPE=PNG:iVBORw0KGgoAAAANSUhEUg==",
      "KEY;ENCODING=b:MIIBIjANBgkqhkiG9w0BAQEFAAO=",
    }, nil, task)
    assert_not_nil(res)
    assert_nil(res.has_encoded_text)
    task:destroy()
  end)

  test("extract_text returns the property values", function()
    local task = get_task()
    local res = vcard.process(make_vcard {
      "VERSION:3.0",
      "FN:Jane Doe",
      "ORG:Example Corp",
    }, nil, task)
    assert_not_nil(res)
    local text = res.extract_text(res)
    assert_not_nil(text)
    assert_true(text:find('jane doe', 1, true) ~= nil,
        "expected FN value in extracted text")
    task:destroy()
  end)

  test("URL injection is capped", function()
    local content_util = require "lua_content/util"
    local task = get_task()
    local lines = { "BEGIN:VCARD", "VERSION:3.0", "FN:Jane Doe" }

    for i = 1, content_util.config.max_urls * 3 do
      lines[#lines + 1] = string.format("URL:http://flood%d.example.com/p", i)
    end

    lines[#lines + 1] = "END:VCARD"
    lines[#lines + 1] = ""

    local res = vcard.process(table.concat(lines, "\r\n"), nil, task)
    assert_not_nil(res)
    assert_equal(#res.urls, content_util.config.max_urls)
    assert_equal(#(task:get_urls() or {}), content_util.config.max_urls)
    task:destroy()
  end)
end)
