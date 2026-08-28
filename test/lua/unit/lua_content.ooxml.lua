-- OOXML (Office Open XML) heuristics (lua_content/ooxml)

context("OOXML attachment heuristics", function()
  local ooxml = require "lua_content/ooxml"
  local rspamd_task = require "rspamd_task"

  local function get_task()
    local _res, task = rspamd_task.load_from_string(
        "From: <>\nTo: <nobody@example.com>\nSubject: test\n\n", rspamd_config)
    task:process_message()
    return task
  end

  -- Stub mime_part exposing only what ooxml.process() consumes:
  -- get_archive():get_files(n) and get_detected_ext().
  --
  -- get_files honours `n` the way the C implementation does
  -- (lua_archive_get_files: max_files = MIN(arch->files->len, max_files)).
  -- Ignoring it would hide the very case the cap reporting turns on: asking
  -- for exactly the cap makes "at the cap" and "past the cap" identical.
  local function make_mpart(files, ext)
    return {
      get_archive = function()
        return {
          get_files = function(_self, n)
            if not n or n >= #files then
              return files
            end

            local out = {}

            for i = 1, n do
              out[i] = files[i]
            end

            return out
          end,
        }
      end,
      get_detected_ext = function()
        return ext
      end,
    }
  end

  test("no archive available returns nil", function()
    local mpart = { get_archive = function() return nil end }
    local res = ooxml.process("PK\3\4somebytes", mpart, {})
    assert_nil(res)
  end)

  test("plain docx with no macros produces no macro flags", function()
    local mpart = make_mpart({
      "[Content_Types].xml",
      "word/document.xml",
      "word/styles.xml",
    }, "docx")
    local res = ooxml.process("PK\3\4somebytes", mpart, {})
    assert_not_nil(res)
    assert_equal(res.tag, 'ooxml')
    assert_equal(res.doc_type, 'word')
    assert_false(res.has_macros)
    assert_false(res.has_macros_by_ext)
  end)

  test("detects vbaProject.bin and macro-enabled extension", function()
    local mpart = make_mpart({
      "[Content_Types].xml",
      "word/document.xml",
      "word/vbaProject.bin",
    }, "docm")
    local res = ooxml.process("PK\3\4somebytes", mpart, {})
    assert_not_nil(res)
    assert_true(res.has_vbaproject)
    assert_true(res.has_macros)
    assert_true(res.has_macros_by_ext)
  end)

  test("detects XLM (Excel 4.0) macro sheets", function()
    local mpart = make_mpart({
      "[Content_Types].xml",
      "xl/workbook.xml",
      "xl/macrosheets/sheet1.xml",
    }, "xlsm")
    local res = ooxml.process("PK\3\4somebytes", mpart, {})
    assert_not_nil(res)
    assert_equal(res.doc_type, 'excel')
    assert_true(res.has_xlm_macros)
    assert_true(res.has_macros)
  end)

  test("detects external links and ActiveX controls", function()
    local mpart = make_mpart({
      "xl/workbook.xml",
      "xl/externalLinks/externalLink1.xml",
      "xl/activeX/activeX1.xml",
    }, "xlsx")
    local res = ooxml.process("PK\3\4somebytes", mpart, {})
    assert_not_nil(res)
    assert_true(res.has_external_links)
    assert_true(res.has_activex)
  end)
  -- LUA_CONTENT_LIMIT states that content went uninspected, so an archive with
  -- exactly as many entries as the cap allows must not raise it: every entry
  -- was scanned. ooxml therefore asks for one more than the cap and reports
  -- only when that extra entry actually comes back.
  local function archive_of(n)
    local files = { "[Content_Types].xml" }

    for i = #files + 1, n do
      files[i] = string.format("word/part%d.xml", i)
    end

    return files
  end

  test("an archive at exactly the file cap is not reported as truncated", function()
    local task = get_task()
    local res = ooxml.process("PK\3\4somebytes", make_mpart(archive_of(500), "docx"), task)

    assert_not_nil(res)
    assert_equal(res.file_count, 500, 'every entry must be scanned')
    local hits = require("lua_content").get_limits(task)
    assert_true(hits == nil or not hits['ooxml:files'],
        'a fully scanned archive must not claim content went uninspected')
    task:destroy()
  end)

  test("an archive past the file cap is reported as truncated", function()
    local task = get_task()
    local res = ooxml.process("PK\3\4somebytes", make_mpart(archive_of(501), "docx"), task)

    assert_not_nil(res)
    assert_equal(res.file_count, 500, 'entries must stop at the cap')
    assert_true(require("lua_content").get_limits(task)['ooxml:files'],
        'a truncated archive must be reported')
    task:destroy()
  end)

  -- A macro hiding past the cap is exactly what the report is for
  test("entries past the cap are not scanned", function()
    local task = get_task()
    local files = archive_of(500)
    files[501] = "word/vbaProject.bin"
    local res = ooxml.process("PK\3\4somebytes", make_mpart(files, "docx"), task)

    assert_not_nil(res)
    assert_false(res.has_vbaproject, 'the entry past the cap must not be seen')
    assert_true(require("lua_content").get_limits(task)['ooxml:files'],
        'and the gap must be reported')
    task:destroy()
  end)
end)
