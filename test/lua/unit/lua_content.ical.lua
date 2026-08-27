-- iCal spam-signal heuristics (lua_content/ical)

context("iCal spam-signal heuristics", function()
  local rspamd_task = require "rspamd_task"
  local ical = require "lua_content/ical"

  local hdrs = "From: <>\nTo: <nobody@example.com>\nSubject: test\n"

  local function get_task()
    local _res, task = rspamd_task.load_from_string(hdrs .. "\n", rspamd_config)
    task:process_message()
    return task
  end

  local function ics(lines)
    return table.concat(lines, "\n") .. "\n"
  end

  test("conforming invite has no anomaly flags", function()
    local task = get_task()
    local input = ics {
      "BEGIN:VCALENDAR",
      "PRODID:-//Google Inc//Google Calendar 70.9054//EN",
      "METHOD:REQUEST",
      "BEGIN:VEVENT",
      "SUMMARY:Team meeting",
      "LOCATION:Conference Room A",
      "END:VEVENT",
      "END:VCALENDAR",
    }
    local res = ical.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.tag, 'ical')
    assert_nil(res.invalid_prodid)
    assert_nil(res.invalid_method)
    assert_nil(res.numeric_location)
    assert_nil(res.immediate_alarm)
    task:destroy()
  end)

  test("missing PRODID is flagged", function()
    local task = get_task()
    local input = ics {
      "BEGIN:VCALENDAR",
      "METHOD:REQUEST",
      "END:VCALENDAR",
    }
    local res = ical.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.invalid_prodid, 'missing')
    task:destroy()
  end)

  test("non-FPI PRODID is flagged", function()
    local task = get_task()
    local input = ics {
      "BEGIN:VCALENDAR",
      "PRODID:MySpamGenerator1.0",
      "METHOD:REQUEST",
      "END:VCALENDAR",
    }
    local res = ical.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.invalid_prodid, 'MySpamGenerator1.0')
    task:destroy()
  end)

  test("invalid METHOD value is flagged", function()
    local task = get_task()
    local input = ics {
      "BEGIN:VCALENDAR",
      "PRODID:-//Test//Test//EN",
      "METHOD:REPLAY",
      "END:VCALENDAR",
    }
    local res = ical.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.invalid_method, 'replay')
    task:destroy()
  end)

  test("numeric-only LOCATION is flagged", function()
    local task = get_task()
    local input = ics {
      "BEGIN:VCALENDAR",
      "PRODID:-//Test//Test//EN",
      "METHOD:REQUEST",
      "BEGIN:VEVENT",
      "LOCATION:+1-555-123-4567",
      "END:VEVENT",
      "END:VCALENDAR",
    }
    local res = ical.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.numeric_location, '+1-555-123-4567')
    task:destroy()
  end)

  test("real-world address LOCATION is not flagged", function()
    local task = get_task()
    local input = ics {
      "BEGIN:VCALENDAR",
      "PRODID:-//Test//Test//EN",
      "METHOD:REQUEST",
      "BEGIN:VEVENT",
      "LOCATION:221B Baker Street",
      "END:VEVENT",
      "END:VCALENDAR",
    }
    local res = ical.process(input, nil, task)
    assert_not_nil(res)
    assert_nil(res.numeric_location)
    task:destroy()
  end)

  test("zero-duration VALARM trigger is flagged", function()
    local task = get_task()
    local input = ics {
      "BEGIN:VCALENDAR",
      "PRODID:-//Test//Test//EN",
      "METHOD:REQUEST",
      "BEGIN:VEVENT",
      "BEGIN:VALARM",
      "TRIGGER:PT0S",
      "END:VALARM",
      "END:VEVENT",
      "END:VCALENDAR",
    }
    local res = ical.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.immediate_alarm, 'pt0s')
    task:destroy()
  end)

  test("normal VALARM trigger is not flagged", function()
    local task = get_task()
    local input = ics {
      "BEGIN:VCALENDAR",
      "PRODID:-//Test//Test//EN",
      "METHOD:REQUEST",
      "BEGIN:VEVENT",
      "BEGIN:VALARM",
      "TRIGGER:-PT15M",
      "END:VALARM",
      "END:VEVENT",
      "END:VCALENDAR",
    }
    local res = ical.process(input, nil, task)
    assert_not_nil(res)
    assert_nil(res.immediate_alarm)
    task:destroy()
  end)

  test("extracts URLs from description/location/url keys", function()
    local task = get_task()
    local input = ics {
      "BEGIN:VCALENDAR",
      "PRODID:-//Test//Test//EN",
      "METHOD:REQUEST",
      "BEGIN:VEVENT",
      "DESCRIPTION:Join here http://evil.example.com/join",
      "END:VEVENT",
      "END:VCALENDAR",
    }
    local res = ical.process(input, nil, task)
    assert_not_nil(res)
    assert_not_nil(res.elts)
    task:destroy()
  end)

  -- A URL hidden behind quoted-printable renders normally in a calendar
  -- client, so it must be decoded before URL extraction runs.
  test("decodes quoted-printable property text", function()
    local task = get_task()
    local input = table.concat({
      "BEGIN:VCALENDAR",
      "VERSION:2.0",
      "PRODID:-//Example Corp//Calendar 1.0//EN",
      "METHOD:REQUEST",
      "BEGIN:VEVENT",
      "UID:1@example.com",
      "SUMMARY:Meeting",
      "DESCRIPTION;ENCODING=QUOTED-PRINTABLE:Join =68=74=74=70=3A=2F=2Fevil=2Eexample=2Ecom=2Fj",
      "END:VEVENT",
      "END:VCALENDAR",
      "",
    }, "\r\n")
    local res = ical.process(input, nil, task)
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

  -- Regression: RFC 5545 3.1.3 defines ENCODING=BASE64 specifically for
  -- ATTACH, so a base64 attachment says nothing about the invite.
  test("base64 ATTACH is not an encoding anomaly", function()
    local task = get_task()
    local input = table.concat({
      "BEGIN:VCALENDAR",
      "VERSION:2.0",
      "PRODID:-//Example Corp//Calendar 1.0//EN",
      "METHOD:REQUEST",
      "BEGIN:VEVENT",
      "UID:1@example.com",
      "SUMMARY:Meeting",
      "ATTACH;ENCODING=BASE64;VALUE=BINARY:iVBORw0KGgoAAAANSUhEUg==",
      "END:VEVENT",
      "END:VCALENDAR",
      "",
    }, "\r\n")
    local res = ical.process(input, nil, task)
    assert_not_nil(res)
    assert_nil(res.has_encoded_text)
    task:destroy()
  end)

  -- The attachment handlers all work to the shared caps in
  -- lua_content/util.lua; iCal parses with LPeg and injects per property, so
  -- it has to honour them explicitly or a synthetic file allocates without
  -- bound and floods every downstream URL consumer.
  local content_util = require "lua_content/util"

  test("URL injection is capped", function()
    local task = get_task()
    local lines = { "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//X//Y//EN" }

    for i = 1, content_util.config.max_urls * 3 do
      lines[#lines + 1] = "BEGIN:VEVENT"
      lines[#lines + 1] = string.format("UID:%d@example.com", i)
      lines[#lines + 1] = string.format("URL:http://flood%d.example.com/p", i)
      lines[#lines + 1] = "END:VEVENT"
    end

    lines[#lines + 1] = "END:VCALENDAR"
    lines[#lines + 1] = ""

    local res = ical.process(table.concat(lines, "\r\n"), nil, task)
    assert_not_nil(res)
    assert_equal(#res.urls, content_util.config.max_urls)
    assert_equal(#(task:get_urls() or {}), content_util.config.max_urls)
    task:destroy()
  end)

  test("input is bounded before parsing", function()
    local task = get_task()
    local pad = string.rep("X", 128)
    local lines = { "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//X//Y//EN" }
    local target = content_util.config.max_processing_size * 2

    for i = 1, math.floor(target / 140) do
      lines[#lines + 1] = "X-PAD" .. i .. ":" .. pad
    end

    lines[#lines + 1] = "END:VCALENDAR"
    lines[#lines + 1] = ""

    local input = table.concat(lines, "\r\n")
    assert_true(#input > content_util.config.max_processing_size)

    local res = ical.process(input, nil, task)
    assert_not_nil(res)
    -- Every element comes from within the cap, so far fewer than were written
    assert_true(#res.elts < math.floor(target / 140),
        'expected the parse to stop at the processing cap')
    task:destroy()
  end)
end)
