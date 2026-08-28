-- CFBF (legacy Office/OLE2) heuristics (lua_content/cfbf)

context("CFBF (OLE2) attachment heuristics", function()
  local rspamd_task = require "rspamd_task"
  local cfbf = require "lua_content/cfbf"

  local hdrs = "From: <>\nTo: <nobody@example.com>\nSubject: test\n"

  local function get_task()
    local _res, task = rspamd_task.load_from_string(hdrs .. "\n", rspamd_config)
    task:process_message()
    return task
  end

  -- Encode an ASCII name as a UTF-16LE, null-padded 64-byte directory name field
  local function name_field(name)
    local parts = {}
    for i = 1, #name do
      parts[#parts + 1] = name:sub(i, i) .. "\0"
    end
    local s = table.concat(parts)
    return s .. string.rep("\0", 64 - #s)
  end

  -- Little-endian uint16/uint32 packers (avoid string.pack: unavailable on LuaJIT/5.1)
  local function u16le(n)
    return string.char(n % 256, math.floor(n / 256) % 256)
  end

  local function u32le(n)
    return string.char(n % 256, math.floor(n / 256) % 256,
        math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
  end

  -- Build a minimal CFBF file. Sector 0 is the first directory sector and
  -- sector 1 is its FAT; optional entries are placed in non-contiguous sector 2.
  --
  -- sec_shift selects the sector size (9 => 512 bytes / major version 3,
  -- 12 => 4096 bytes / major version 4). The 512-byte header is padded out to
  -- a full sector in both cases, which is what makes sector 0 start at one
  -- whole sector into the file rather than at byte 512.
  local function make_cfbf(entries, extra_tail, chained_entries, sec_shift)
    sec_shift = sec_shift or 9
    local sec_size = math.floor(2 ^ sec_shift)
    local header = {}
    header[1] = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" -- magic, bytes 1-8
    header[2] = string.rep("\0", 20)                -- bytes 9-28 (CLSID + minor/major ver placeholder trimmed below)
    -- Bytes 29-30: BOM (0xFFFE little endian)
    header[3] = "\xFE\xFF"
    -- Bytes 31-32: sector shift
    header[4] = u16le(sec_shift)
    -- NumberOfFATSectors = 1 at bytes 45..48
    local used = #table.concat(header)
    header[#header + 1] = string.rep("\0", 45 - 1 - used)
    header[#header + 1] = u32le(1)
    -- FirstDirectorySectorID = 0 (directory sector right after the header)
    header[#header + 1] = u32le(0)
    local hdr = table.concat(header) .. string.rep("\0", 76 - #table.concat(header))
    -- Header DIFAT entry: sector 1 is the FAT sector.
    hdr = hdr .. u32le(1) .. string.rep("\0", sec_size - #hdr - 4)
    assert(#hdr == sec_size)

    local function make_dir_sector(dir_entries)
      local dir = {}
      for _, e in ipairs(dir_entries) do
      local entry = name_field(e.name)
      entry = entry .. u16le((#e.name + 1) * 2) -- name length incl. null terminator
      entry = entry .. string.char(e.dtype)  -- object type byte at offset 66 (0-indexed)
      entry = entry .. string.rep("\0", 128 - #entry)
      dir[#dir + 1] = entry
      end
      return table.concat(dir) .. string.rep("\0", sec_size - #table.concat(dir))
    end

    local dirdata = make_dir_sector(entries)
    local fat = u32le(chained_entries and 2 or 0xFFFFFFFE)
        .. u32le(0xFFFFFFFD)
        .. u32le(0xFFFFFFFE)
        .. string.rep("\xFF", sec_size - 12)
    local chained_dir = chained_entries and make_dir_sector(chained_entries) or ""

    return hdr .. dirdata .. fat .. chained_dir .. (extra_tail or "")
  end

  test("non-CFBF input returns nil", function()
    local task = get_task()
    local res = cfbf.process("not a compound file at all, way too short", nil, task)
    assert_nil(res)
    task:destroy()
  end)

  test("detects Word document type without VBA", function()
    local task = get_task()
    local input = make_cfbf({
      { name = "WordDocument", dtype = 2 },
      { name = "SummaryInformation", dtype = 2 },
    })
    local res = cfbf.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.tag, 'cfbf')
    assert_equal(res.doc_type, 'word')
    assert_false(res.has_vba)
    task:destroy()
  end)

  test("detects VBA macro storage", function()
    local task = get_task()
    local input = make_cfbf({
      { name = "WordDocument", dtype = 2 },
      { name = "Macros", dtype = 1 },
      { name = "VBA", dtype = 1 },
    })
    local res = cfbf.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_vba)
    task:destroy()
  end)

  -- MS-CFB pads the 512-byte header out to a full sector, so with 4096-byte
  -- sectors (major version 4) sector 0 begins at byte 4096, not at 512. Reading
  -- it at 512 lands in header padding and the directory walk finds nothing.
  test("parses a major version 4 document with 4096 byte sectors", function()
    local task = get_task()
    local input = make_cfbf({
      { name = "WordDocument", dtype = 2 },
      { name = "Macros", dtype = 1 },
      { name = "VBA", dtype = 1 },
    }, nil, nil, 12)
    local res = cfbf.process(input, nil, task)
    assert_not_nil(res, '4096 byte sectors must parse')
    assert_equal(res.doc_type, 'word', '4096 byte sectors')
    assert_true(res.has_vba, '4096 byte sectors')
    task:destroy()
  end)

  test("follows a non-contiguous directory FAT chain", function()
    local task = get_task()
    local input = make_cfbf({
      { name = "WordDocument", dtype = 2 },
    }, nil, {
      { name = "VBA", dtype = 1 },
    })
    local res = cfbf.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_vba)
    task:destroy()
  end)

  test("detects suspicious VBA (auto-exec + execution primitive)", function()
    local task = get_task()
    local tail = "AutoOpen" .. string.rep("\0", 8) .. 'Shell(' .. string.rep("\0", 8)
    local input = make_cfbf({
      { name = "WordDocument", dtype = 2 },
      { name = "VBA", dtype = 1 },
    }, tail)
    local res = cfbf.process(input, nil, task)
    assert_not_nil(res)
    assert_true(res.has_vba)
    assert_true(res.has_suspicious_vba)
    task:destroy()
  end)

  test("detects Outlook MSG document type", function()
    local task = get_task()
    local input = make_cfbf({
      { name = "__properties_version1.0", dtype = 5 },
      { name = "__substg1.0_0037001F", dtype = 2 },
    })
    local res = cfbf.process(input, nil, task)
    assert_not_nil(res)
    assert_equal(res.doc_type, 'msg')
    task:destroy()
  end)
  -- The directory walk stops after CFBF_MAX_DIR_SECTORS sectors. A chain of
  -- exactly that many is complete, so it must not be reported as truncated;
  -- only a chain that would have continued means storage went unseen.
  --
  -- Needs a real multi-sector layout rather than the three-sector one above:
  -- sectors 0..n-1 hold the directory, the FAT sectors follow, and the header
  -- DIFAT points at them.
  local function make_cfbf_chain(nsectors, last_entries)
    local sec_size = 512
    local entries_per_fat = sec_size / 4
    local nfat = 1

    while math.ceil((nsectors + nfat) / entries_per_fat) > nfat do
      nfat = nfat + 1
    end

    local hdr = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" .. string.rep("\0", 20)
        .. "\xFE\xFF" .. u16le(9)
    hdr = hdr .. string.rep("\0", 44 - #hdr)
        .. u32le(nfat)   -- NumberOfFATSectors, bytes 45-48
        .. u32le(0)      -- FirstDirectorySectorID, bytes 49-52
    hdr = hdr .. string.rep("\0", 76 - #hdr)

    -- Header DIFAT: the FAT sectors sit directly after the directory
    local difat = {}
    for i = 0, nfat - 1 do
      difat[#difat + 1] = u32le(nsectors + i)
    end
    hdr = hdr .. table.concat(difat)
    hdr = hdr .. string.rep("\xFF", sec_size - #hdr)
    assert(#hdr == sec_size)

    local function dir_sector(dir_entries)
      local dir = {}
      for _, e in ipairs(dir_entries or {}) do
        local entry = name_field(e.name) .. u16le((#e.name + 1) * 2)
            .. string.char(e.dtype)
        dir[#dir + 1] = entry .. string.rep("\0", 128 - #entry)
      end
      return table.concat(dir) .. string.rep("\0", sec_size - #table.concat(dir))
    end

    local out = { hdr }
    out[#out + 1] = dir_sector({ { name = "WordDocument", dtype = 2 } })

    for i = 2, nsectors - 1 do
      out[#out + 1] = dir_sector(nil)
    end

    if nsectors > 1 then
      out[#out + 1] = dir_sector(last_entries)
    end

    -- FAT: the directory chain runs 0 -> 1 -> ... -> nsectors-1, then ends
    local fat = {}
    for i = 0, nsectors - 2 do
      fat[#fat + 1] = u32le(i + 1)
    end
    fat[#fat + 1] = u32le(0xFFFFFFFE)           -- ENDOFCHAIN
    for _ = 1, nfat do
      fat[#fat + 1] = u32le(0xFFFFFFFD)         -- FATSECT
    end
    local fatstr = table.concat(fat)
    fatstr = fatstr .. string.rep("\xFF", nfat * sec_size - #fatstr)

    out[#out + 1] = fatstr

    return table.concat(out)
  end

  test("a directory chain at exactly the sector cap is not reported as truncated", function()
    local task = get_task()
    local res = cfbf.process(make_cfbf_chain(1024, { { name = "VBA", dtype = 1 } }), nil, task)

    assert_not_nil(res, '1024 sectors must parse')
    assert_true(res.has_vba, 'the last sector is still within the cap')
    local hits = require("lua_content").get_limits(task)
    assert_true(hits == nil or not hits['cfbf:dir_sectors'],
        'a fully walked chain must not claim content went unseen')
    task:destroy()
  end)

  test("a directory chain past the sector cap is reported as truncated", function()
    local task = get_task()
    local res = cfbf.process(make_cfbf_chain(1025, { { name = "VBA", dtype = 1 } }), nil, task)

    assert_not_nil(res, '1025 sectors must parse')
    assert_false(res.has_vba, 'the sector past the cap must not be walked')
    assert_true(require("lua_content").get_limits(task)['cfbf:dir_sectors'],
        'and the gap must be reported')
    task:destroy()
  end)
end)
