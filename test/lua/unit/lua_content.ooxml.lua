-- OOXML (Office Open XML) heuristics (lua_content/ooxml)

context("OOXML attachment heuristics", function()
  local ooxml = require "lua_content/ooxml"

  -- Stub mime_part exposing only what ooxml.process() consumes:
  -- get_archive():get_files(n) and get_detected_ext().
  local function make_mpart(files, ext)
    return {
      get_archive = function()
        return {
          get_files = function(_self, _n)
            return files
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
end)
