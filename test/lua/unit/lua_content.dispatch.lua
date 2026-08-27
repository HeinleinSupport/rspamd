-- Content-module dispatch rules (lua_content/init)
--
-- These cover which MIME parts reach a content handler at all, which is easy
-- to regress: mime_part:is_attachment() is false for any part that carries
-- neither Content-Disposition: attachment nor a filename, and that describes
-- the normal inline form of a calendar invite and a vCard.

context("lua_content part dispatch", function()
  local rspamd_task = require "rspamd_task"

  local function scan(msg)
    local _res, task = rspamd_task.load_from_string(msg, rspamd_config)
    task:process_message()
    return task
  end

  -- Returns the `tag` of the specific content extracted from the first part
  -- that has any, or nil.
  local function first_specific_tag(task)
    for _, part in ipairs(task:get_parts()) do
      local spec = part:get_specific()

      if spec and type(spec) == 'table' and spec.tag then
        return spec.tag
      end
    end

    return nil
  end

  local ical_body = table.concat({
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//Example Corp//Calendar 1.0//EN",
    "METHOD:REQUEST",
    "BEGIN:VEVENT",
    "UID:1234@example.com",
    "DTSTART:20260101T120000Z",
    "SUMMARY:Test meeting",
    "END:VEVENT",
    "END:VCALENDAR",
  }, "\r\n")

  -- An inline text/calendar inside multipart/alternative is how essentially
  -- every calendar client sends an invite: no Content-Disposition, no
  -- filename, so is_attachment() is false. It must still be processed.
  test("inline text/calendar is processed", function()
    local msg = table.concat({
      "From: <sender@example.com>",
      "To: <nobody@example.com>",
      "Subject: invite",
      "MIME-Version: 1.0",
      'Content-Type: multipart/alternative; boundary="BOUND"',
      "",
      "--BOUND",
      "Content-Type: text/plain",
      "",
      "You are invited",
      "",
      "--BOUND",
      "Content-Type: text/calendar; method=REQUEST",
      "",
      ical_body,
      "",
      "--BOUND--",
      "",
    }, "\r\n")

    local task = scan(msg)
    assert_equal(first_specific_tag(task), 'ical')
    task:destroy()
  end)

  test("text/calendar sent as an attachment is processed", function()
    local msg = table.concat({
      "From: <sender@example.com>",
      "To: <nobody@example.com>",
      "Subject: invite",
      "MIME-Version: 1.0",
      'Content-Type: text/calendar; name="invite.ics"',
      'Content-Disposition: attachment; filename="invite.ics"',
      "",
      ical_body,
      "",
    }, "\r\n")

    local task = scan(msg)
    assert_equal(first_specific_tag(task), 'ical')
    task:destroy()
  end)

  -- An inline text/html body part is already handled by rspamd's built-in
  -- HTML parser, so the html content handler must not run over it again.
  test("inline text/html is not processed by the html handler", function()
    local msg = table.concat({
      "From: <sender@example.com>",
      "To: <nobody@example.com>",
      "Subject: newsletter",
      "MIME-Version: 1.0",
      "Content-Type: text/html",
      "",
      "<html><body><script>x()</script><a href='http://example.com/'>hi</a></body></html>",
      "",
    }, "\r\n")

    local task = scan(msg)
    assert_nil(first_specific_tag(task))
    task:destroy()
  end)

  test("text/html sent as an attachment is processed", function()
    local msg = table.concat({
      "From: <sender@example.com>",
      "To: <nobody@example.com>",
      "Subject: invoice",
      "MIME-Version: 1.0",
      'Content-Type: text/html; name="invoice.html"',
      'Content-Disposition: attachment; filename="invoice.html"',
      "",
      "<html><body><script>x()</script></body></html>",
      "",
    }, "\r\n")

    local task = scan(msg)
    assert_equal(first_specific_tag(task), 'html')
    task:destroy()
  end)

  -- Regression: rspamd_archives_process() marks ZIP parts as
  -- RSPAMD_MIME_PART_ARCHIVE before the lua_content hook runs. While the hook
  -- was restricted to UNDEFINED parts, and while lua specific data aliased the
  -- archive pointer inside the part_type union, no ZIP-based format could
  -- reach a content handler at all, which left the whole ooxml module dead.
  test("ooxml archive attachment reaches the content handler", function()
    local rspamd_util = require "rspamd_util"

  -- A minimal macro-enabled OOXML package: [Content_Types].xml plus
  -- word/document.xml and word/vbaProject.bin, base64 encoded.
  local docx_b64 = table.concat({
    'UEsDBBQAAAAIAAAAIVyi7cddawAAAHMAAAATAAAAW0NvbnRlbnRfVHlwZXNdLnhtbBWMwQ3C',
    'MAwAV4n8bx14IISa9scEZYAomLSC2FFsIdie8Dzd6ablU17uTU134QCH0YMjTnLfOQe4rdfh',
    'DMs8rd9K6nrKGmAzqxdETRuVqKNU4m4e0kq0ji1jjekZM+HR+xMmYSO2wf4PwPkHUEsDBBQA',
    'AAAIAAAAIVzaFmF/egAAAI8AAAARAAAAd29yZC9kb2N1bWVudC54bWxFzEEOwiAQheGrEPZ2',
    '0IUxBOiuJ9ADIGBLUmYIoOjtxZXLl//lU/M77ewVSo2Emh8nwVlARz7iqvntuhwufDaqS0/u',
    'mQI2Nv5YZdd8ay1LgOq2kGydKAcc7UEl2TZmWaFT8bmQC7UOLu1wEuIMyUbkP/JO/gNGwR83',
    'X1BLAwQUAAAACAAAACFcNmONdQYAAABAAAAAEwAAAHdvcmQvdmJhUHJvamVjdC5iaW5jYKAM',
    'AABQSwECFAMUAAAACAAAACFcou3HXWsAAABzAAAAEwAAAAAAAAAAAAAAgAEAAAAAW0NvbnRl',
    'bnRfVHlwZXNdLnhtbFBLAQIUAxQAAAAIAAAAIVzaFmF/egAAAI8AAAARAAAAAAAAAAAAAACA',
    'AZwAAAB3b3JkL2RvY3VtZW50LnhtbFBLAQIUAxQAAAAIAAAAIVw2Y411BgAAAEAAAAATAAAA',
    'AAAAAAAAAACAAUUBAAB3b3JkL3ZiYVByb2plY3QuYmluUEsFBgAAAAADAAMAwQAAAHwBAAAA',
    'AA==',
  })

    local msg = table.concat({
      "From: <sender@example.com>",
      "To: <nobody@example.com>",
      "Subject: doc",
      "MIME-Version: 1.0",
      'Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document; name="a.docx"',
      'Content-Disposition: attachment; filename="a.docx"',
      "Content-Transfer-Encoding: base64",
      "",
      docx_b64,
      "",
    }, "\r\n")

    local task = scan(msg)
    local ooxml_spec, saw_archive = nil, false

    for _, part in ipairs(task:get_parts()) do
      local spec = part:get_specific()

      if spec and type(spec) == 'table' and spec.tag == 'ooxml' then
        ooxml_spec = spec
      end

      -- The archive must still be readable afterwards: lua specific data and
      -- the archive pointer used to alias one another, so storing either one
      -- destroyed the other
      if part:get_archive() then
        saw_archive = true
      end
    end

    assert_not_nil(ooxml_spec, "ooxml handler did not run for a docx attachment")
    assert_true(ooxml_spec.has_vbaproject, "vbaProject.bin was not detected")
    assert_equal(ooxml_spec.doc_type, 'word')
    assert_true(saw_archive, "archive data did not survive set_specific()")
    task:destroy()
  end)

  -- A handler error unwinds before part:set_specific() runs, which leaves the
  -- part looking exactly like one no handler claimed. Every symbol of that
  -- content type then stops firing with nothing but a log line to show for it,
  -- so the dispatcher must contain the error and record it.
  local two_attachments = table.concat({
    "From: <sender@example.com>",
    "To: <nobody@example.com>",
    "Subject: invoice",
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="OUT"',
    "",
    "--OUT",
    'Content-Type: text/html; name="invoice.html"',
    'Content-Disposition: attachment; filename="invoice.html"',
    "",
    "<html><body><script>x()</script></body></html>",
    "",
    "--OUT",
    'Content-Type: application/rtf; name="a.rtf"',
    'Content-Disposition: attachment; filename="a.rtf"',
    "",
    [[{\rtf1\ansi {\*\objdata 0105000002}}]],
    "",
    "--OUT--",
    "",
  }, "\r\n")

  local function specific_tags(task)
    local tags = {}

    for _, part in ipairs(task:get_parts()) do
      local spec = part:get_specific()

      if spec and type(spec) == 'table' and spec.tag then
        tags[spec.tag] = true
      end
    end

    return tags
  end

  test("a failing handler does not stop the other handlers", function()
    local lua_content = require "lua_content"
    local html = require "lua_content/html"
    local saved = html.process
    html.process = function() error("simulated handler bug", 0) end

    local ok, err = pcall(function()
      local task = scan(two_attachments)
      local tags = specific_tags(task)

      assert_nil(tags.html, "the failing handler must not have stored content")
      assert_true(tags.rtf, "an unrelated handler must still run")

      local failures = lua_content.get_failures(task)
      assert_not_nil(failures, "the failure must be recorded")
      assert_not_nil(failures.html, "the failure must name the module")
      task:destroy()
    end)

    html.process = saved
    assert_true(ok, tostring(err))
  end)

  test("no failures are recorded when every handler succeeds", function()
    local lua_content = require "lua_content"
    local task = scan(two_attachments)
    local tags = specific_tags(task)

    assert_true(tags.html)
    assert_true(tags.rtf)
    assert_nil(lua_content.get_failures(task))
    task:destroy()
  end)

  -- Regression for the actual outage: lua_util.is_debug_enabled() ships with
  -- lua_content, so a deployment that overlays lualib/lua_content/ onto an
  -- installed rspamd without replacing lualib/lua_util.lua used to take every
  -- content handler down at once.
  test("handlers survive a lua_util without is_debug_enabled", function()
    local lua_util = require "lua_util"
    local saved = lua_util.is_debug_enabled
    lua_util.is_debug_enabled = nil

    local ok, err = pcall(function()
      local task = scan(two_attachments)
      local tags = specific_tags(task)

      assert_true(tags.html, "html handler must still run")
      assert_true(tags.rtf, "rtf handler must still run")
      task:destroy()
    end)

    lua_util.is_debug_enabled = saved
    assert_true(ok, tostring(err))
  end)
end)
