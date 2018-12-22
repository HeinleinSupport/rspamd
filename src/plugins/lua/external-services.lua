--[[
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2018, Carsten Rosenberg <c.rosenberg@heinlein-support.de>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]] --

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local rspamd_regexp = require "rspamd_regexp"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local lua_util = require "lua_util"
local fun = require "fun"
local ucl = require "ucl"
local redis_params

local N = "external-services"

if confighelp then
  rspamd_config:add_example(nil, 'external-services',
    "Check messages for viruses",
    [[
external-services {
  # multiple scanners could be checked, for each we create a configuration block with an arbitrary name
  clamav {
    # If set force this action if any virus is found (default unset: no action is forced)
    # action = "reject";
    # If set, then rejection message is set to this value (mention single quotes)
    # message = '${SCANNER}: virus found: "${VIRUS}"';
    # Scan mime_parts seperately - otherwise the complete mail will be transfered to AV Scanner
    #scan_mime_parts = true;
    # Scanning Text is suitable for some av scanner databases (e.g. Sanesecurity)
    #scan_text_mime = false;
    #scan_image_mime = false;
    # If `max_size` is set, messages > n bytes in size are not scanned
    max_size = 20000000;
    # symbol to add (add it to metric if you want non-zero weight)
    symbol = "CLAM_VIRUS";
    # type of scanner: "clamav", "fprot", "sophos" or "savapi"
    type = "clamav";
    # For "savapi" you must also specify the following variable
    product_id = 12345;
    # You can enable logging for clean messages
    log_clean = true;
    # servers to query (if port is unspecified, scanner-specific default is used)
    # can be specified multiple times to pool servers
    # can be set to a path to a unix socket
    # Enable this in local.d/external-services.conf
    servers = "127.0.0.1:3310";
    # if `patterns` is specified virus name will be matched against provided regexes and the related
    # symbol will be yielded if a match is found. If no match is found, default symbol is yielded.
    patterns {
      # symbol_name = "pattern";
      JUST_EICAR = "^Eicar-Test-Signature$";
    }
    # `whitelist` points to a map of IP addresses. Mail from these addresses is not scanned.
    whitelist = "/etc/rspamd/external-services.wl";
  }
}
]])
  return
end

local default_message = '${SCANNER}: virus found: "${VIRUS}"'

local function text_parts_min_words(task, min_words)
  local text_parts_empty = true
  local text_parts = task:get_text_parts()

  local filter_func = function(p)
    return p:get_words_count() >= min_words
  end

  fun.each(function(p)
    text_parts_empty = false
  end, fun.filter(filter_func, text_parts))

  return text_parts_empty

end

local function match_patterns(default_sym, found, patterns, score)
  if type(patterns) ~= 'table' then return default_sym, score end
  if not patterns[1] then
    for sym, pat in pairs(patterns) do
      if pat:match(found) then
        return sym, '1'
      end
    end
    return default_sym,score
  else
    for _, p in ipairs(patterns) do
      for sym, pat in pairs(p) do
        if pat:match(found) then
          return sym, '1'
        end
      end
    end
    return default_sym,score
  end
end

local function yield_result(task, rule, vname, score)
  local all_whitelisted = true
  if type(vname) == 'string' then
    local symname,symscore = match_patterns(rule['symbol'], vname, rule['patterns'], score)
    if rule['whitelist'] and rule['whitelist']:get_key(vname) then
      rspamd_logger.infox(task, '%s: "%s" is in whitelist', rule['type'], vname)
      return
    end
    task:insert_result(symname, symscore, vname)
    rspamd_logger.infox(task, '%s: %s found: "%s" - score %s', rule['type'],
      rule['detection_category'], vname, symscore)
  elseif type(vname) == 'table' then
    for _, vn in ipairs(vname) do
      local symname,symscore = match_patterns(rule['symbol'], vn, rule['patterns'], score)
      if rule['whitelist'] and rule['whitelist']:get_key(vn) then
        rspamd_logger.infox(task, '%s: "%s" is in whitelist', rule['type'], vn)
      else
        all_whitelisted = false
        task:insert_result(symname, symscore, vn)
        rspamd_logger.infox(task, '%s: %s found: "%s" - score %s', rule['type'],
          rule['detection_category'], vn, symscore)
      end
    end
  end
  if rule['action'] and rule['action'] == 'reject' then
    if type(vname) == 'table' then
      if all_whitelisted then return end
      vname = table.concat(vname, '; ')
    end
    task:set_pre_result(rule['action'],
        lua_util.template(rule.message or 'Rejected', {
          SCANNER = rule['type'],
          VIRUS = vname,
        }), N)
  end
end

local function clamav_config(opts)
  local clamav_conf = {
    scan_mime_parts = false,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 3310,
    log_clean = false,
    timeout = 15.0,
    retransmits = 2,
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
    detection_category = "virus",
    default_score = 1,
  }

  clamav_conf = lua_util.override_defaults(clamav_conf, opts)

  if not clamav_conf.prefix then
    clamav_conf.prefix = 'rs_av_' .. clamav_conf.name .. '_'
  end

  if not clamav_conf.log_prefix then
    clamav_conf.log_prefix = clamav_conf.name .. ' (' .. clamav_conf.type .. ')'
  end

  if not clamav_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  clamav_conf['upstreams'] = upstream_list.create(rspamd_config,
    clamav_conf['servers'],
    clamav_conf.default_port)

  if clamav_conf['upstreams'] then
    return clamav_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    clamav_conf['servers'])
  return nil
end

local function fprot_config(opts)
  local fprot_conf = {
    scan_mime_parts = false,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 10200,
    timeout = 15.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
    detection_category = "virus",
    default_score = 1,
  }

  fprot_conf = lua_util.override_defaults(fprot_conf, opts)

  if not fprot_conf.prefix then
    fprot_conf.prefix = 'rs_av_' .. fprot_conf.name .. '_'
  end

  if not fprot_conf.log_prefix then
    fprot_conf.log_prefix = fprot_conf.name .. ' (' .. fprot_conf.type .. ')'
  end

  if not fprot_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  fprot_conf['upstreams'] = upstream_list.create(rspamd_config,
    fprot_conf['servers'],
    fprot_conf.default_port)

  if fprot_conf['upstreams'] then
    return fprot_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    fprot_conf['servers'])
  return nil
end

local function sophos_config(opts)
  local sophos_conf = {
    scan_mime_parts = false,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 4010,
    timeout = 15.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
    detection_category = "virus",
    default_score = 1,
    savdi_report_encrypted = false,
    savdi_report_oversize = false,
  }

  sophos_conf = lua_util.override_defaults(sophos_conf, opts)

  if not sophos_conf.prefix then
    sophos_conf.prefix = 'rs_av_' .. sophos_conf.name .. '_'
  end

  if not sophos_conf.log_prefix then
    sophos_conf.log_prefix = sophos_conf.name .. ' (' .. sophos_conf.type .. ')'
  end

  if not sophos_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  sophos_conf['upstreams'] = upstream_list.create(rspamd_config,
    sophos_conf['servers'],
    sophos_conf.default_port)

  if sophos_conf['upstreams'] then
    return sophos_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    sophos_conf['servers'])
  return nil
end

local function savapi_config(opts)
  local savapi_conf = {
    scan_mime_parts = false,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 4444, -- note: You must set ListenAddress in savapi.conf
    product_id = 0,
    log_clean = false,
    timeout = 15.0,
    retransmits = 2,
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
    detection_category = "virus",
    default_score = 1,
  }

  savapi_conf = lua_util.override_defaults(savapi_conf, opts)

  if not savapi_conf.prefix then
    savapi_conf.prefix = 'rs_av_' .. savapi_conf.name .. '_'
  end

  if not savapi_conf.log_prefix then
    savapi_conf.log_prefix = savapi_conf.name .. ' (' .. savapi_conf.type .. ')'
  end

  if not savapi_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  savapi_conf['upstreams'] = upstream_list.create(rspamd_config,
    savapi_conf['servers'],
    savapi_conf.default_port)

  if savapi_conf['upstreams'] then
    return savapi_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    savapi_conf['servers'])
  return nil
end

local function kaspersky_config(opts)
  local kaspersky_conf = {
    scan_mime_parts = true;
    scan_text_mime = false;
    scan_image_mime = false;
    product_id = 0,
    log_clean = false,
    timeout = 5.0,
    retransmits = 1, -- use local files, retransmits are useless
    cache_expire = 3600, -- expire redis in one hour
    message = default_message,
    detection_category = "virus",
    default_score = 1,
    tmpdir = '/tmp',
  }

  kaspersky_conf = lua_util.override_defaults(kaspersky_conf, opts)

  if not kaspersky_conf.prefix then
    kaspersky_conf.prefix = 'rs_av_' .. kaspersky_conf.name .. '_'
  end

  if not kaspersky_conf.log_prefix then
    kaspersky_conf.log_prefix = kaspersky_conf.name .. ' (' .. kaspersky_conf.type .. ')'
  end

  if not kaspersky_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  kaspersky_conf['upstreams'] = upstream_list.create(rspamd_config,
      kaspersky_conf['servers'], 0)

  if kaspersky_conf['upstreams'] then
    return kaspersky_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      kaspersky_conf['servers'])
  return nil
end

local function dcc_config(opts)

  local dcc_conf = {
    scan_mime_parts = false,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 10045,
    timeout = 15.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 3600, -- expire redis in one hour
    message = '${SCANNER}: bulk message found: "${VIRUS}"',
    detection_category = "hash",
    default_score = 1,
    action = false,
    client = '0.0.0.0',
  }

  dcc_conf = lua_util.override_defaults(dcc_conf, opts)

  if not dcc_conf.prefix then
    dcc_conf.prefix = 'rs_av_' .. dcc_conf.name .. '_'
  end

  if not dcc_conf.log_prefix then
    dcc_conf.log_prefix = dcc_conf.name .. ' (' .. dcc_conf.type .. ')'
  end

  if not dcc_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  dcc_conf['upstreams'] = upstream_list.create(rspamd_config,
    dcc_conf['servers'],
    dcc_conf.default_port)

  if dcc_conf['upstreams'] then
    return dcc_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    dcc_conf['servers'])
  return nil
end

local function pyzor_config(opts)

  local pyzor_conf = {
    scan_mime_parts = false,
    scan_text_mime = false,
    scan_image_mime = false,
    text_part_min_words = 2,
    default_port = 5953,
    timeout = 15.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 7200, -- expire redis in one hour
    message = '${SCANNER}: Pyzor bulk message found: "${VIRUS}"',
    detection_category = "hash",
    default_score = 1,
    action = false,
  }

  pyzor_conf = lua_util.override_defaults(pyzor_conf, opts)

  if not pyzor_conf.prefix then
    pyzor_conf.prefix = 'rs_av_' .. pyzor_conf.name .. '_'
  end

  if not pyzor_conf.log_prefix then
    pyzor_conf.log_prefix = pyzor_conf.name .. ' (' .. pyzor_conf.type .. ')'
  end

  if not pyzor_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  pyzor_conf['upstreams'] = upstream_list.create(rspamd_config,
    pyzor_conf['servers'],
    pyzor_conf.default_port)

  if pyzor_conf['upstreams'] then
    return pyzor_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    pyzor_conf['servers'])
  return nil
end

local function oletools_config(opts)

  local oletools_conf = {
    scan_mime_parts = false,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 5954,
    timeout = 15.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 7200, -- expire redis in 2h
    message = '${SCANNER}: Oletools threat message found: "${VIRUS}"',
    detection_category = "office macro",
    oletools_flags = "A.X";
    default_score = 1,
    action = false,
  }

  oletools_conf = lua_util.override_defaults(oletools_conf, opts)

  if not oletools_conf.prefix then
    oletools_conf.prefix = 'rs_av_' .. oletools_conf.name .. '_'
  end

  if not oletools_conf.log_prefix then
    oletools_conf.log_prefix = oletools_conf.name .. ' (' .. oletools_conf.type .. ')'
  end

  if not oletools_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  oletools_conf['upstreams'] = upstream_list.create(rspamd_config,
    oletools_conf['servers'],
    oletools_conf.default_port)

  if oletools_conf['upstreams'] then
    return oletools_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    oletools_conf['servers'])
  return nil
end


local function razor_config(opts)

  local razor_conf = {
    scan_mime_parts = false,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 9192,
    timeout = 15.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 7200, -- expire redis in one hour
    message = '${SCANNER}: Razor bulk message found: "${VIRUS}"',
    detection_category = "hash",
    default_score = 1,
    action = false,
  }

  razor_conf = lua_util.override_defaults(razor_conf, opts)

  if not razor_conf.prefix then
    razor_conf.prefix = 'rs_av_' .. razor_conf.name .. '_'
  end

  if not razor_conf.log_prefix then
    razor_conf.log_prefix = razor_conf.name .. ' (' .. razor_conf.type .. ')'
  end

  if not razor_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  razor_conf['upstreams'] = upstream_list.create(rspamd_config,
    razor_conf['servers'],
    razor_conf.default_port)

  if razor_conf['upstreams'] then
    return razor_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    razor_conf['servers'])
  return nil
end

local function spamassassin_config(opts)

  local spamassassin_conf = {
    scan_mime_parts = false,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 783,
    timeout = 15.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 7200, -- expire redis in one hour
    message = '${SCANNER}: Spamassassin bulk message found: "${VIRUS}"',
    detection_category = "spam",
    default_score = 1,
    action = false,
    symbol = "SPAMD_V",
  }

  spamassassin_conf = lua_util.override_defaults(spamassassin_conf, opts)

  if not spamassassin_conf.prefix then
    spamassassin_conf.prefix = 'rs_av_' .. spamassassin_conf.name .. '_'
  end

  if not spamassassin_conf.log_prefix then
    spamassassin_conf.log_prefix = spamassassin_conf.name .. ' (' .. spamassassin_conf.type .. ')'
  end

  if not spamassassin_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  spamassassin_conf['upstreams'] = upstream_list.create(rspamd_config,
    spamassassin_conf['servers'],
    spamassassin_conf.default_port)

  if spamassassin_conf['upstreams'] then
    return spamassassin_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    spamassassin_conf['servers'])
  return nil
end

local function icap_config(opts)

  local icap_conf = {
    scan_mime_parts = true,
    scan_all_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    scheme = "scan",
    default_port = 4020,
    timeout = 15.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 7200, -- expire redis in one hour
    message = '${SCANNER}: threat found with icap scanner: "${VIRUS}"',
    detection_category = "virus",
    default_score = 1,
    action = false,
    symbol = "ICAP_V",
  }

  icap_conf = lua_util.override_defaults(icap_conf, opts)

  if not icap_conf.prefix then
    icap_conf.prefix = 'rs_av_' .. icap_conf.name .. '_'
  end

  if not icap_conf.log_prefix then
    icap_conf.log_prefix = icap_conf.name .. ' (' .. icap_conf.type .. ')'
  end

  if not icap_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  icap_conf['upstreams'] = upstream_list.create(rspamd_config,
    icap_conf['servers'],
    icap_conf.default_port)

  if icap_conf['upstreams'] then
    return icap_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    icap_conf['servers'])
  return nil
end

local function message_not_too_large(task, content, rule)
  local max_size = tonumber(rule['max_size'])
  if not max_size then return true end
  if #content > max_size then
    rspamd_logger.infox("skip %s AV check as it is too large: %s (%s is allowed)",
      rule.type, #content, max_size)
    return false
  end
  return true
end

local function need_av_check(task, content, rule)
  return message_not_too_large(task, content, rule)
end

local function check_av_cache(task, digest, rule, fn)
  local key = digest

  local function redis_av_cb(err, data)
    if data and type(data) == 'string' then
      -- Cached
      data = rspamd_str_split(data, '\t')
      local threat_string = rspamd_str_split(data[1], '\v')
      local score = data[2] or rule.default_score
      if threat_string[1] ~= 'OK' then
        lua_util.debugm(N, task, '%s: got cached threat result for %s: %s', rule.log_prefix, key, threat_string[1])
        yield_result(task, rule, threat_string, score)
      else
        lua_util.debugm(N, task, '%s: got cached negative result for %s: %s', rule.log_prefix, key, threat_string[1])
      end
    else
      if err then
        rspamd_logger.errx(task, 'Got error checking cache: %1', err)
      end
      fn()
    end
  end

  if redis_params then

    key = rule['prefix'] .. key

    if rspamd_redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      false, -- is write
      redis_av_cb, --callback
      'GET', -- command
      {key} -- arguments)
    ) then
      return true
    end
  end

  return false
end

local function save_av_cache(task, digest, rule, to_save, score)
  local key = digest

  local function redis_set_cb(err)
    -- Do nothing
    if err then
      rspamd_logger.errx(task, 'failed to save virus cache for %s -> "%s": %s',
        to_save, key, err)
    else
      lua_util.debugm(N, task, '%s: saved cached result for %s: %s', rule.log_prefix, key, to_save)
    end
  end

  if type(to_save) == 'table' then
    to_save = table.concat(to_save, '\v')
  end

  local value = table.concat({to_save, score}, '\t')

  if redis_params then
    key = rule['prefix'] .. key

    rspamd_redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      true, -- is write
      redis_set_cb, --callback
      'SETEX', -- command
      { key, rule['cache_expire'], value }
    )
  end

  return false
end

local function fprot_check(task, content, digest, rule)
  local function fprot_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local scan_id = task:get_queue_id()
    if not scan_id then scan_id = task:get_uid() end
    local header = string.format('SCAN STREAM %s SIZE %d\n', scan_id,
        #content)
    local footer = '\n'

    local function fprot_callback(err, data)
      if err then
        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()

          lua_util.debugm(N, task, '%s: retry IP: %s', rule.log_prefix, addr)

          tcp.request({
            task = task,
            host = addr:to_string(),
            port = addr:get_port(),
            timeout = rule['timeout'],
            callback = fprot_callback,
            data = { header, content, footer },
            stop_pattern = '\n'
          })
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
          task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and retransmits exceed')
        end
      else
        upstream:ok()
        data = tostring(data)
        local cached
        local clean = string.match(data, '^0 <clean>')
        if clean then
          cached = 'OK'
          if rule['log_clean'] then
            rspamd_logger.infox(task, '%s: message or mime_part is clean', rule['symbol'], rule['type'])
          end
        else
          -- returncodes: 1: infected, 2: suspicious, 3: both, 4-255: some error occured
          -- see http://www.f-prot.com/support/helpfiles/unix/appendix_c.html for more detail
          local vname = string.match(data, '^[1-3] <[%w%s]-: (.-)>')
          if not vname then
            rspamd_logger.errx(task, 'Unhandled response: %s', data)
          else
            yield_result(task, rule, vname, rule.default_score)
            cached = vname
          end
        end
        if cached then
          save_av_cache(task, digest, rule, cached, rule.default_score)
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      callback = fprot_callback,
      data = { header, content, footer },
      stop_pattern = '\n'
    })
  end

  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, fprot_check_uncached) then
      return
    else
      fprot_check_uncached()
    end
  end
end

local function clamav_check(task, content, digest, rule)
  local function clamav_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local header = rspamd_util.pack("c9 c1 >I4", "zINSTREAM", "\0",
      #content)
    local footer = rspamd_util.pack(">I4", 0)

    local function clamav_callback(err, data)
      if err then

        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()

          lua_util.debugm(N, task, '%s: retry IP: %s', rule.log_prefix, addr)

          tcp.request({
            task = task,
            host = addr:to_string(),
            port = addr:get_port(),
            timeout = rule['timeout'],
            callback = clamav_callback,
            data = { header, content, footer },
            stop_pattern = '\0'
          })
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
          task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and retransmits exceed')
        end

      else
        upstream:ok()
        data = tostring(data)
        lua_util.debugm(N, task, '%s: got reply: %s', rule.log_prefix, data)
        if data == 'stream: OK' then
          if rule['log_clean'] then
            rspamd_logger.infox(task, '%s: message or mime_part is clean', rule['symbol'], rule['type'])
          else
            lua_util.debugm(N, task, '%s: message or mime_part is clean', rule['symbol'], rule['type'])
          end
          save_av_cache(task, digest, rule, 'OK', 0)
        else
          local vname = string.match(data, 'stream: (.+) FOUND')
          if vname then
            yield_result(task, rule, vname, rule.default_score)
            save_av_cache(task, digest, rule, vname, rule.default_score)
          else
            rspamd_logger.errx(task, 'unhandled response: %s', data)
            task:insert_result(rule['symbol_fail'], 0.0, 'unhandled response')
          end
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      callback = clamav_callback,
      data = { header, content, footer },
      stop_pattern = '\0'
    })
  end

  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, clamav_check_uncached) then
      return
    else
      clamav_check_uncached()
    end
  end
end

local function sophos_check(task, content, digest, rule)
  local function sophos_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local protocol = 'SSSP/1.0\n'
    local streamsize = string.format('SCANDATA %d\n', #content)
    local bye = 'BYE\n'

    local function sophos_callback(err, data, conn)

      if err then

          -- set current upstream to fail because an error occurred
          upstream:fail()

          -- retry with another upstream until retransmits exceeds
          if retransmits > 0 then

            retransmits = retransmits - 1

            -- Select a different upstream!
            upstream = rule.upstreams:get_upstream_round_robin()
            addr = upstream:get_addr()

            lua_util.debugm(N, task, '%s: retry IP: %s', rule.log_prefix, addr)

            tcp.request({
              task = task,
              host = addr:to_string(),
              port = addr:get_port(),
              timeout = rule['timeout'],
              callback = sophos_callback,
              data = { protocol, streamsize, content, bye }
            })
          else
            rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
            task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and retransmits exceed')
          end
      else
        upstream:ok()
        data = tostring(data)
        lua_util.debugm(N, task, '%s: got reply: %s', rule.log_prefix, data)
        local vname = string.match(data, 'VIRUS (%S+) ')
        if vname then
          yield_result(task, rule, vname, rule.default_score)
          save_av_cache(task, digest, rule, vname, rule.default_score)
        else
          if string.find(data, 'DONE OK') then
            if rule['log_clean'] then
              rspamd_logger.infox(task, '%s: message or mime_part is clean', rule['symbol'], rule['type'])
            else
              lua_util.debugm(N, task, '%s: message or mime_part is clean', rule['symbol'], rule['type'])
            end
            save_av_cache(task, digest, rule, 'OK', 0)
            -- not finished - continue
          elseif string.find(data, 'ACC') or string.find(data, 'OK SSSP') then
            conn:add_read(sophos_callback)
            -- set pseudo virus if configured, else do nothing since it's no fatal
          elseif string.find(data, 'FAIL 0212') then
            rspamd_logger.infox(task, 'Message is ENCRYPTED (0212 SOPHOS_SAVI_ERROR_FILE_ENCRYPTED): %s', data)
            if rule['savdi_report_encrypted'] then
              yield_result(task, rule, "SAVDI_FILE_ENCRYPTED", rule.default_score)
              save_av_cache(task, digest, rule, "SAVDI_FILE_ENCRYPTED", rule.default_score)
            end
            -- set pseudo virus if configured, else set fail since part was not scanned
          elseif string.find(data, 'REJ 4') then
            if rule['savdi_report_oversize'] then
              rspamd_logger.infox(task, 'SAVDI: Message is OVERSIZED (SSSP reject code 4): %s', data)
              yield_result(task, rule, "SAVDI_FILE_OVERSIZED", rule.default_score)
              save_av_cache(task, digest, rule, "SAVDI_FILE_OVERSIZED", rule.default_score)
            else
              rspamd_logger.errx(task, 'SAVDI: Message is OVERSIZED (SSSP reject code 4): %s', data)
              task:insert_result(rule['symbol_fail'], 0.0, 'Message is OVERSIZED (SSSP reject code 4):' .. data)
            end
            -- excplicitly set REJ1 message when SAVDIreports a protocol error
          elseif string.find(data, 'REJ 1') then
            rspamd_logger.errx(task, 'SAVDI (Protocol error (REJ 1)): %s', data)
            task:insert_result(rule['symbol_fail'], 0.0, 'SAVDI (Protocol error (REJ 1)):' .. data)
          else
            rspamd_logger.errx(task, 'SAVDI unhandled response: %s', data)
            task:insert_result(rule['symbol_fail'], 0.0, 'unhandled response')
          end

        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      callback = sophos_callback,
      data = { protocol, streamsize, content, bye }
    })
  end

  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, sophos_check_uncached) then
      return
    else
      sophos_check_uncached()
    end
  end
end

local function savapi_check(task, content, digest, rule)
  local function savapi_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local fname = string.format('%s/%s.tmp',
        rule.tmpdir, rspamd_util.random_hex(32))
    local message_fd = rspamd_util.create_file(fname)

    if not message_fd then
      rspamd_logger.errx('cannot store file for savapi scan: %s', fname)
      return
    end

    if type(content) == 'string' then
      -- Create rspamd_text
      local rspamd_text = require "rspamd_text"
      content = rspamd_text.fromstring(content)
    end
    content:save_in_file(message_fd)

    -- Ensure cleanup
    task:get_mempool():add_destructor(function()
      os.remove(fname)
      rspamd_util.close_file(message_fd)
    end)

    local vnames = {}

    -- Forward declaration for recursive calls
    local savapi_scan1_cb

    local function savapi_fin_cb(err, conn)
      local vnames_reordered = {}
      -- Swap table
      for virus,_ in pairs(vnames) do
        table.insert(vnames_reordered, virus)
      end
      lua_util.debugm(N, task, "%s: number of virus names found %s", rule['type'], #vnames_reordered)
      if #vnames_reordered > 0 then
        local vname = {}
        for _,virus in ipairs(vnames_reordered) do
          table.insert(vname, virus)
        end

        yield_result(task, rule, vname, rule.default_score)
        save_av_cache(task, digest, rule, vname, rule.default_score)
      end
      if conn then
        conn:close()
      end
    end

    local function savapi_scan2_cb(err, data, conn)
      local result = tostring(data)
      lua_util.debugm(N, task, "%s: got reply: %s",
        rule['type'], result)

      -- Terminal response - clean
      if string.find(result, '200') or string.find(result, '210') then
        if rule['log_clean'] then
          rspamd_logger.infox(task, '%s: message or mime_part is clean', rule['type'])
        end
        save_av_cache(task, digest, rule, 'OK')
        conn:add_write(savapi_fin_cb, 'QUIT\n')

      -- Terminal response - infected
      elseif string.find(result, '319') then
        conn:add_write(savapi_fin_cb, 'QUIT\n')

      -- Non-terminal response
      elseif string.find(result, '310') then
        local virus
        virus = result:match "310.*<<<%s(.*)%s+;.*;.*"
        if not virus then
          virus = result:match "310%s(.*)%s+;.*;.*"
          if not virus then
            rspamd_logger.errx(task, "%s: virus result unparseable: %s",
                rule['type'], result)
            return
          end
        end
        -- Store unique virus names
        vnames[virus] = 1
        -- More content is expected
        conn:add_write(savapi_scan1_cb, '\n')
      end
    end

    savapi_scan1_cb = function(err, conn)
      conn:add_read(savapi_scan2_cb, '\n')
    end

    -- 100 PRODUCT:xyz
    local function savapi_greet2_cb(err, data, conn)
      local result = tostring(data)
      if string.find(result, '100 PRODUCT') then
        lua_util.debugm(N, task, "%s: scanning file: %s",
            rule['type'], fname)
        conn:add_write(savapi_scan1_cb, {string.format('SCAN %s\n',
            fname)})
      else
        rspamd_logger.errx(task, '%s: invalid product id %s', rule['type'],
            rule['product_id'])
        conn:add_write(savapi_fin_cb, 'QUIT\n')
      end
    end

    local function savapi_greet1_cb(err, conn)
      conn:add_read(savapi_greet2_cb, '\n')
    end

    local function savapi_callback_init(err, data, conn)
      if err then

        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()

          lua_util.debugm(N, task, '%s: retry IP: %s', rule.log_prefix, addr)

          tcp.request({
            task = task,
            host = addr:to_string(),
            port = addr:get_port(),
            timeout = rule['timeout'],
            callback = savapi_callback_init,
            stop_pattern = {'\n'},
          })
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
          task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and retransmits exceed')
        end
      else
        upstream:ok()
        local result = tostring(data)

        -- 100 SAVAPI:4.0 greeting
        if string.find(result, '100') then
          conn:add_write(savapi_greet1_cb, {string.format('SET PRODUCT %s\n', rule['product_id'])})
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      callback = savapi_callback_init,
      stop_pattern = {'\n'},
    })
  end

  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, savapi_check_uncached) then
      return
    else
      savapi_check_uncached()
    end
  end
end

local function kaspersky_check(task, content, digest, rule)
  local function kaspersky_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local fname = string.format('%s/%s.tmp',
        rule.tmpdir, rspamd_util.random_hex(32))
    local message_fd = rspamd_util.create_file(fname)
    local clamav_compat_cmd = string.format("nSCAN %s\n", fname)

    if not message_fd then
      rspamd_logger.errx('cannot store file for kaspersky scan: %s', fname)
      return
    end

    if type(content) == 'string' then
      -- Create rspamd_text
      local rspamd_text = require "rspamd_text"
      content = rspamd_text.fromstring(content)
    end
    content:save_in_file(message_fd)

    -- Ensure file cleanup
    task:get_mempool():add_destructor(function()
      os.remove(fname)
      rspamd_util.close_file(message_fd)
    end)


    local function kaspersky_callback(err, data)
      if err then
        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()

          lua_util.debugm(N, task,
              '%s: retry IP: %s', rule.log_prefix, addr)

          tcp.request({
            task = task,
            host = addr:to_string(),
            port = addr:get_port(),
            timeout = rule['timeout'],
            callback = kaspersky_callback,
            data = { clamav_compat_cmd },
            stop_pattern = '\n'
          })
        else
          rspamd_logger.errx(task,
              '%s: failed to scan, maximum retransmits exceed',
              rule['symbol'], rule['type'])
          task:insert_result(rule['symbol_fail'], 0.0,
              'failed to scan and retransmits exceed')
        end

      else
        upstream:ok()
        data = tostring(data)
        local cached
        lua_util.debugm(N, task, '%s: got reply: %s',
            rule.log_prefix, data)
        if data == 'stream: OK' then
          cached = 'OK'
          if rule['log_clean'] then
            rspamd_logger.infox(task, '%s: message or mime_part is clean',
                rule['symbol'], rule['type'])
          else
            lua_util.debugm(N, task, '%s: message or mime_part is clean',
                rule['symbol'], rule['type'])
          end
        else
          local vname = string.match(data, ': (.+) FOUND')
          if vname then
            yield_result(task, rule, vname)
            cached = vname
          else
            rspamd_logger.errx(task, 'unhandled response: %s', data)
            task:insert_result(rule['symbol_fail'], 0.0, 'unhandled response')
          end
        end
        if cached then
          save_av_cache(task, digest, rule, cached)
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      callback = kaspersky_callback,
      data = { clamav_compat_cmd },
      stop_pattern = '\n'
    })
  end

  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, kaspersky_check_uncached) then
      return
    else
      kaspersky_check_uncached()
    end
  end
end

local function dcc_check(task, content, digest, rule)
  local function dcc_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local client =  rule.client

    local client_ip = task:get_from_ip()
    if client_ip and client_ip:is_valid() then
      client = client_ip:to_string()
    end
    local client_host = task:get_hostname()
    if client_host then
      client = client .. "\r" .. client_host
    end

    -- HELO
    local helo = task:get_helo() or ''

    -- Envelope From
    local ef = task:get_from()
    local envfrom = 'test@example.com'
    if ef and ef[1] then
      envfrom = ef[1]['addr']
    end

    -- Envelope To
    local envrcpt = 'test@example.com'
    local rcpts = task:get_recipients();
    if rcpts then
      local dcc_recipients = table.concat(fun.totable(fun.map(function(rcpt)
        return rcpt['addr'] end,
      rcpts)), '\n')
      if dcc_recipients then
        envrcpt = dcc_recipients
      end
    end

    -- Build the DCC query
    -- https://www.dcc-servers.net/dcc/dcc-tree/dccifd.html#Protocol
    local request_data = {
      "header\n",
      client .. "\n",
      helo .. "\n",
      envfrom .. "\n",
      envrcpt .. "\n",
      "\n",
      content
    }

    local function dcc_callback(err, data, conn)

      if err then

          -- set current upstream to fail because an error occurred
          upstream:fail()

          -- retry with another upstream until retransmits exceeds
          if retransmits > 0 then

            retransmits = retransmits - 1

            -- Select a different upstream!
            upstream = rule.upstreams:get_upstream_round_robin()
            addr = upstream:get_addr()

            lua_util.debugm(N, task, '%s: retry IP: %s', rule.log_prefix, addr)

            tcp.request({
              task = task,
              host = addr:to_string(),
              port = addr:get_port(),
              timeout = rule.timeout or 2.0,
              shutdown = true,
              data = request_data,
              callback = dcc_callback
            })
          else
            rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
            task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and retransmits exceed')
          end
      else
        -- Parse the response
        if upstream then upstream:ok() end
        local _,_,result,disposition,header = tostring(data):find("(.-)\n(.-)\n(.-)\n")
        lua_util.debugm(N, task, 'DCC result=%1 disposition=%2 header="%3"',
          result, disposition, header)

        --[[
        @todo: Implement math function to calc the score dynamically based on return values. Maybe check spamassassin implementation.
        ]] --

        if header then
          local _,_,info = header:find("; (.-)$")
          if (result == 'R') then
            -- Reject
            yield_result(task, rule, info, rule.default_score)
            save_av_cache(task, digest, rule, info, rule.default_score)
          elseif (result == 'T') then
            -- Temporary failure
            rspamd_logger.warnx(task, 'DCC returned a temporary failure result: %s', result)
            task:insert_result(rule['symbol_fail'], 0.0, 'DCC returned a temporary failure result:' .. result)
          elseif result == 'A' then
            -- do nothing
            if rule.log_clean then
              rspamd_logger.infox(task, '%s: clean, returned result A - info: %s', rule.log_prefix, info)
            else
              lua_util.debugm(N, task, '%s: returned result A - info: %s', rule.log_prefix, info)
            end
            save_av_cache(task, digest, rule, 'OK')
          elseif result == 'G' then
            -- do nothing
            if rule.log_clean then
              rspamd_logger.infox(task, '%s: clean, returned result G - info: %s', rule.log_prefix, info)
            else
              lua_util.debugm(N, task, '%s: returned result G - info: %s', rule.log_prefix, info)
            end
            save_av_cache(task, digest, rule, 'OK')
          elseif result == 'S' then
            -- do nothing
            if rule.log_clean then
              rspamd_logger.infox(task, '%s: clean, returned result S - info: %s', rule.log_prefix, info)
            else
              lua_util.debugm(N, task, '%s: returned result S - info: %s', rule.log_prefix, info)
            end
            save_av_cache(task, digest, rule, 'OK')
          else
            -- Unknown result
            rspamd_logger.warnx(task, 'DCC result error: %1', result);
            task:insert_result(rule['symbol_fail'], 0.0, 'DCC result error: ' .. result)
          end
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule.timeout or 2.0,
      shutdown = true,
      data = request_data,
      callback = dcc_callback
    })
  end
  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, dcc_check_uncached) then
      return
    else
      dcc_check_uncached()
    end
  end
end

local function pyzor_check(task, content, digest, rule)
  local function pyzor_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits

    local function pyzor_callback(err, data, conn)

      if err then

          -- set current upstream to fail because an error occurred
          upstream:fail()

          -- retry with another upstream until retransmits exceeds
          if retransmits > 0 then

            retransmits = retransmits - 1

            -- Select a different upstream!
            upstream = rule.upstreams:get_upstream_round_robin()
            addr = upstream:get_addr()

            lua_util.debugm(N, task, '%s: retry IP: %s:%s err: %s', rule.log_prefix, addr, addr:get_port(), err)

            tcp.request({
              task = task,
              host = addr:to_string(),
              port = addr:get_port(),
              timeout = rule['timeout'],
              shutdown = true,
              data = { "CHECK\n" , content },
              callback = pyzor_callback,
            })
          else
            rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
            task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and retransmits exceed')
          end
      else
        -- Parse the response
        if upstream then upstream:ok() end

        lua_util.debugm(N, task, '%s: returned data: %s', rule.log_prefix, tostring(data))
        local ucl_parser = ucl.parser()
        local ok, py_err = ucl_parser:parse_string(tostring(data))
        if not ok then
            rspamd_logger.errx(task, "error parsing response: %s", py_err)
            return
        end

        local resp = ucl_parser:get_object()
        local whitelisted = tonumber(resp["WL-Count"])
        local reported = tonumber(resp["Count"])

        --rspamd_logger.infox(task, "%s - count=%s wl=%s", addr:to_string(), reported, whitelisted)

        --[[
        @todo: Implement math function to calc the score dynamically based on return values. Maybe check spamassassin implementation.
        ]] --
        local entries = reported - whitelisted

        local weight = 0
        local bl = 0
        local wl = 0

        if entries >= 100 then
            weight = 1.5
            bl = 100
        elseif entries >= 25 then
            weight = 1.25
            bl = 25
        elseif entries >= 5 then
            weight = 1.0
            bl = 5
        elseif entries >= 1 and whitelisted == 0 then
            weight = 0.2
            bl = 1
        end

        if whitelisted >= 100 then
            wl = 100
        elseif whitelisted >= 25 then
            wl = 25
        elseif whitelisted >= 5 then
            wl = 5
        elseif whitelisted >= 1 then
            wl = 1
        end

        local info = string.format("count=%d wl=%d", reported, whitelisted)
        local threat_string = string.format("bl_%d_wl_%d", reported, whitelisted)

        if weight > 0 then
          lua_util.debugm(N, task, '%s: returned result is spam - info: %s', rule.log_prefix, info)
          yield_result(task, rule, threat_string, weight)
          save_av_cache(task, digest, rule, threat_string, weight)
        else
          if rule.log_clean then
            rspamd_logger.infox(task, '%s: clean, returned result is ham - info: %s', rule.log_prefix, info)
          else
            lua_util.debugm(N, task, '%s: returned result is ham - info: %s', rule.log_prefix, info)
          end
          save_av_cache(task, digest, rule, 'OK', weight)
        end

      end
    end

    if text_parts_min_words(task, rule.text_part_min_words) then
      rspamd_logger.infox(task, '%s: #words is less then text_part_min_words: %s',
        rule.log_prefix, rule.text_part_min_words)
      return
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      shutdown = true,
      data = { "CHECK\n" , content },
      callback = pyzor_callback,
    })
  end
  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, pyzor_check_uncached) then
      return
    else
      pyzor_check_uncached()
    end
  end
end

local function oletools_check(task, content, digest, rule)
  local function oletools_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits

    local function oletools_callback(err, data, conn)

      if err then

          -- set current upstream to fail because an error occurred
          upstream:fail()

          -- retry with another upstream until retransmits exceeds
          if retransmits > 0 then

            retransmits = retransmits - 1

            -- Select a different upstream!
            upstream = rule.upstreams:get_upstream_round_robin()
            addr = upstream:get_addr()

            lua_util.debugm(N, task, '%s: retry IP: %s:%s err: %s', rule.log_prefix, addr, addr:get_port(), err)

            tcp.request({
              task = task,
              host = addr:to_string(),
              port = addr:get_port(),
              timeout = rule['timeout'],
              shutdown = true,
              --data = { "CHECK\n" , content },
              data = content,
              callback = oletools_callback,
            })
          else
            rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
            task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and retransmits exceed')
          end
      else
        -- Parse the response
        if upstream then upstream:ok() end

        data = tostring(data)
        lua_util.debugm(N, task, 'data: %s', tostring(data))

        local lines = rspamd_str_split(data, "\r\n")

        lua_util.debugm(N, task, '%s: line6: %s', rule.log_prefix, lines[6])
        lua_util.debugm(N, task, '%s: line7: %s', rule.log_prefix, lines[7])
        lua_util.debugm(N, task, '%s: line8: %s', rule.log_prefix, lines[8])

        local flag_line = lines[6] or ''
        local matches_line = lines[7]..lines[8] or ''
        local error_line = lines[8] or ''
        local error_line2 = lines[9] or ''
        local flags
        local matches
        if string.find(flag_line, 'SUSPICIOUS') then
          -- SUSPICIOUS|AWX  |OLE:|49574.1544728465.877461
          -- MacroRaptor 0.53 - http://decalage.info/python/oletools
          -- This is work in progress, please report issues at https://github.com/decalage2/oletools/issues
          -- ----------+-----+----+--------------------------------------------------------
          -- Result    |Flags|Type|File
          -- ----------+-----+----+--------------------------------------------------------
          -- SUSPICIOUS|A-X  |OpX:|1545402678.0867093.44346
          --           |     |    |Matches: ['cmdCancel_Click', 'Declare Function
          --           |     |    |OpenClipboard Lib']
          local pattern_symbols = "(SUSPICIOUS%|)(.*)(  %|...:%|.*)"
          local flags_string = string.gsub(flag_line, pattern_symbols, "%2")
          lua_util.debugm(N, task, '%s: flags_returned: |%s|', rule.log_prefix, flags_string)
          flags = string.match(flags_string, rule.oletools_flags)
          lua_util.debugm(N, task, '%s: flags: |%s|', rule.log_prefix, flags)

          if string.find(matches_line, 'Matches') then
            --           |     |    |Matches: ['Document_open', 'copyfile', 'CreateObject']
            matches_line = string.gsub(matches_line, "%s|", " ")
            lua_util.debugm(N, task, '%s: matches_line: |%s|', rule.log_prefix, matches_line)
            local pattern_matches = "(.*Matches: %[)(.*)(%].*)"
            matches = string.gsub(matches_line, pattern_matches, "%2")
            matches = string.gsub(matches, "[%s%']", "")
            lua_util.debugm(N, task, '%s: matches: |%s|', rule.log_prefix, matches)
          end
        elseif string.find(flag_line, 'ERROR') then

          -- MacroRaptor 0.53 - http://decalage.info/python/oletools
          -- This is work in progress, please report issues at https://github.com/decalage2/oletools/issues
          -- ----------+-----+----+--------------------------------------------------------
          -- Result    |Flags|Type|File
          -- ----------+-----+----+--------------------------------------------------------
          -- ERROR     |     |??? |/tmp/oletools//1545021249.743918.30108
          --           |     |    |Failed to open file
          --           |     |    |/tmp/oletools//1545021249.743918.30108 is RTF, need to
          --           |     |    |run rtfobj.py and find VBA Macros in its output.
          -- Flags: A=AutoExec, W=Write, X=Execute

          -- MacroRaptor 0.53 - http://decalage.info/python/oletools
          -- This is work in progress, please report issues at https://github.com/decalage2/oletools/issues
          -- ----------+-----+----+--------------------------------------------------------
          -- Result    |Flags|Type|File
          -- ----------+-----+----+--------------------------------------------------------
          -- ERROR     |     |??? |/tmp/oletools//1545028202.5934522.28846
          --           |     |    |Failed to open file
          --           |     |    |/tmp/oletools//1545028202.5934522.28846 is not a
          --           |     |    |supported file type, cannot extract VBA Macros.

          local pattern_symbols = "( *%| *%| *%|)(.*)$"
          local error_string = string.gsub(error_line, pattern_symbols, "%2")
          local error_string2 = string.gsub(error_line2, pattern_symbols, "%2")
          lua_util.debugm(N, task, '%s: ERROR: %s %s', rule.log_prefix, error_string, error_string2)
          rspamd_logger.warnx(task, '%s: oletools returned ERROR', rule['symbol'], rule['type'])
        elseif rule.log_clean and string.find(flag_line, 'No Macro') then
          rspamd_logger.infox(task, '%s: clean, document has no macro', rule['symbol'], rule['type'])
        elseif rule.log_clean and string.find(flag_line, 'Macro OK') then
          rspamd_logger.infox(task, '%s: clean, document has macro, but nothing suspicious', rule['symbol'], rule['type'])
        else
          rspamd_logger.warnx(task, '%s: unhandled response', rule['symbol'], rule['type'])
        end

        if flags ~= nil then
          lua_util.debugm(N, task, '%s: threat_string: |%s|', rule.log_prefix, flags .. ',' .. matches)
          local threat_table = {flags}
          local matches_table = rspamd_str_split(matches, ",")
          for _,m in ipairs(matches_table) do
            table.insert(threat_table, m)
          end
          yield_result(task, rule, threat_table, rule.default_score)
          save_av_cache(task, digest, rule, threat_table, rule.default_score)
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      shutdown = true,
      --data = { "CHECK\n" , content },
      data = content,
      callback = oletools_callback,
    })
  end
  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, oletools_check_uncached) then
      return
    else
      oletools_check_uncached()
    end
  end
end


local function razor_check(task, content, digest, rule)
  local function razor_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits

    local function razor_callback(err, data, conn)

      if err then

          -- set current upstream to fail because an error occurred
          upstream:fail()

          -- retry with another upstream until retransmits exceeds
          if retransmits > 0 then

            retransmits = retransmits - 1

            -- Select a different upstream!
            upstream = rule.upstreams:get_upstream_round_robin()
            addr = upstream:get_addr()

            lua_util.debugm(N, task, '%s: retry IP: %s:%s err: %s', rule.log_prefix, addr, addr:get_port(), err)

            tcp.request({
              task = task,
              host = addr:to_string(),
              port = addr:get_port(),
              timeout = rule['timeout'],
              shutdown = true,
              data = content,
              callback = razor_callback,
            })
          else
            rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
            task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and retransmits exceed')
          end
      else
        -- Parse the response
        if upstream then upstream:ok() end

        --[[
        @todo: Razorsocket currently only returns ham or spam. When the wrapper is fixed we should add dynamic scores here.
        Maybe check spamassassin implementation.
        ]] --

        local threat_string = tostring(data)
        if threat_string == "spam" then
          task:insert_result(rule['symbol'], 1.0)
          lua_util.debugm(N, task, '%s: returned result is spam', rule['symbol'], rule['type'])
          yield_result(task, rule, threat_string, rule.default_score)
          save_av_cache(task, digest, rule, threat_string, rule.default_score)
        elseif threat_string == "ham" then
          if rule.log_clean then
            rspamd_logger.infox(task, '%s: returned result is ham', rule['symbol'], rule['type'])
          else
            lua_util.debugm(N, task, '%s: returned result is ham', rule['symbol'], rule['type'])
          end
          save_av_cache(task, digest, rule, 'OK', rule.default_score)
        else
          rspamd_logger.errx(task,"%s - unknown response from razorsocket: %s", addr:to_string(), threat_string)
        end

      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      shutdown = true,
      data = content,
      callback = razor_callback,
    })
  end
  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, razor_check_uncached) then
      return
    else
      razor_check_uncached()
    end
  end
end

local function spamassassin_check(task, content, digest, rule)
  local function spamassassin_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits

    -- Build the spamd query
    -- https://svn.apache.org/repos/asf/spamassassin/trunk/spamd/PROTOCOL
    local request_data = {
      "HEADERS SPAMC/1.5\r\n",
      "User: root\r\n",
      "Content-length: ".. #content .. "\r\n",
      "\r\n",
      content,
    }
    --lua_util.debugm(N, task, '%s: get_content: %s', rule.log_prefix, task:get_content())
    --lua_util.debugm(N, task, '%s: request_data: %s', rule.log_prefix, request_data)

    local function spamassassin_callback(err, data, conn)

      if err then

          -- set current upstream to fail because an error occurred
          upstream:fail()

          -- retry with another upstream until retransmits exceeds
          if retransmits > 0 then

            retransmits = retransmits - 1

            -- Select a different upstream!
            upstream = rule.upstreams:get_upstream_round_robin()
            addr = upstream:get_addr()

            lua_util.debugm(N, task, '%s: retry IP: %s:%s err: %s', rule.log_prefix, addr, addr:get_port(), err)

            tcp.request({
              task = task,
              host = addr:to_string(),
              port = addr:get_port(),
              timeout = rule['timeout'],
              data = request_data,
              callback = spamassassin_callback,
            })
          else
            rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
            task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and retransmits exceed')
          end
      else
        -- Parse the response
        if upstream then upstream:ok() end

        --lua_util.debugm(N, task, '%s: returned result: %s', rule.log_prefix, data)

        --[[
        Spam: False ; 1.1 / 5.0

        X-Spam-Status: No, score=1.1 required=5.0 tests=HTML_MESSAGE,MIME_HTML_ONLY,
          TVD_RCVD_SPACE_BRACKET,UNPARSEABLE_RELAY autolearn=no
          autolearn_force=no version=3.4.2
        ]] --
        local header = string.gsub(tostring(data), "[\r\n]+[\t ]", " ")
        --lua_util.debugm(N, task, '%s: returned header: %s', rule.log_prefix, header)

        local symbols
        local spam_score
        for s in header:gmatch("[^\r\n]+") do
            if string.find(s, 'Spam: .* / 5.0') then
              local pattern_symbols = "(Spam:.*; )(%-?%d?%d%.%d)( / 5%.0)"
              spam_score = string.gsub(s, pattern_symbols, "%2")
              lua_util.debugm(N, task, '%s: spamd Spam line: %s', rule.log_prefix, spam_score)
            end
            if string.find(s, 'X%-Spam%-Status') then
              local pattern_symbols = "(.*X%-Spam%-Status.*tests%=)(.*)(autolearn%=.*version%=%d%.%d%.%d.*)"
              symbols = string.gsub(s, pattern_symbols, "%2")
              symbols = string.gsub(symbols, "%s", "")
            end
        end

        if tonumber(spam_score) > 0 and #symbols > 0 and symbols ~= "none" then
          local symbols_table = {}
          symbols_table = rspamd_str_split(symbols, ",")
          lua_util.debugm(N, task, '%s: returned symbols as table: %s', rule.log_prefix, symbols_table)

          yield_result(task, rule, symbols_table, spam_score)
          save_av_cache(task, digest, rule, symbols_table, spam_score)
        else
          if rule.log_clean then
            rspamd_logger.infox(task, '%s: clean, no spam detected', rule['symbol'], rule['type'])
          else
            lua_util.debugm(N, task, '%s: no spam detected - spam score: %s, symbols: %s', rule.log_prefix, spam_score, symbols)
          end
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      data = request_data,
      callback = spamassassin_callback,
    })
  end
  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, spamassassin_check_uncached) then
      return
    else
      spamassassin_check_uncached()
    end
  end
end

local function icap_check(task, content, digest, rule)
  local function icap_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits

    -- Build the icap query
    --lua_util.debugm(N, task, '%s: size: %s - %s', rule.log_prefix, tonumber(task:get_size()), string.format('%02X', string.byte(task:get_size())))
    local size = string.format("%x", tonumber(#content))
    local respond_request = {
      "RESPMOD icap://" .. addr:to_string() .. ":" .. addr:get_port() .. "/" .. rule.scheme .. " ICAP/1.0\r\n",
      "Encapsulated: res-body=0\r\n",
      "\r\n",
      size .. "\r\n",
      content,
      "\r\n0\r\n\r\n",
    }
    lua_util.debugm(N, task, '%s: addr: |%s|%s|', rule.log_prefix, addr:to_string(), addr:get_port())
    local options_request = {
      "OPTIONS icap://" .. addr:to_string() .. ":" .. addr:get_port() .. "/" .. rule.scheme .. " ICAP/1.0\r\n",
      "Host:" .. addr:to_string() .. "\r\n",
      "User-Agent: Rspamd\r\n",
      "Encapsulated: null-body=0\r\n\r\n",
    }

    local function icap_parse_result(result)

      -- Parse the response
      local threat_string = {}
      lua_util.debugm(N, task, '%s: returned result: %s', rule.log_prefix, string.gsub(result, "\r\n", ", "))

      --[[
        X-Virus-ID: Troj/DocDl-OYC
        X-Infection-Found: Type=0; Resolution=2; Threat=Troj/DocDl-OYC;
        X-Infection-Found: Type=0; Resolution=2; Threat=W97M.Downloader;
        X-Infection-Found: Type=2; Resolution=2; Threat=Container size violation
        X-Infection-Found: Type=2; Resolution=2; Threat=Encrypted container violation;
      ]] --
      for s in result:gmatch("[^\r\n]+") do
          if string.find(s, 'X%-Virus%-ID') then
            local pattern_symbols = "(X%-Virus%-ID: )(.*)"
            local match = string.gsub(s, pattern_symbols, "%2")
            lua_util.debugm(N, task, '%s: icap X-Virus-ID: %s', rule.log_prefix, match)
            table.insert(threat_string, match)
          end
          if string.find(s, 'X%-Infection%-Found') then
            local pattern_symbols = "(X%-Infection%-Found: Type%=%d; .* Threat%=)(.*)([;]+)"
            local match = string.gsub(s, pattern_symbols, "%2")
            lua_util.debugm(N, task, '%s: icap X-Infection-Found: %s', rule.log_prefix, match)
            table.insert(threat_string, match)
          end
      end

      if #threat_string >= 1 then
        yield_result(task, rule, threat_string, rule.default_score)
        save_av_cache(task, digest, rule, threat_string, rule.default_score)
      end
    end

    local function icap_r_respond_cb(err, data, conn)
      local result = tostring(data)
      --lua_util.debugm(N, task, '%s: icap_r_respond_cb: |%s|%s|%s|', rule.log_prefix, data, err, conn)
      --lua_util.debugm(N, task, '%s: icap_r_respond_cb result: |%s|', rule.log_prefix, string.gsub(result, "\r\n", ", "))
      conn:close()
      if string.find(result, 'ICAP%/1%.0') then
        icap_parse_result(result)
      else
        lua_util.debugm(N, task, '%s: OPTIONS: No OK in return: |%s|', rule.log_prefix, string.gsub(result, "\r\n", ", "))
      end
    end

    local function icap_w_respond_cb(err, conn)
      conn:add_read(icap_r_respond_cb, '\r\n\r\n')
      --lua_util.debugm(N, task, '%s: icap_w_respond_cb: |%s|%s|', rule.log_prefix, err, conn)
    end

    local function icap_r_options_cb(err, data, conn)
      local result = tostring(data)
      --lua_util.debugm(N, task, '%s: icap_r_options_cb: |%s|%s|%s|', rule.log_prefix, data, err, conn)
      --lua_util.debugm(N, task, '%s: icap_r_options_cb result: |%s|', rule.log_prefix, string.gsub(result, "\r\n", ""))
      if string.find(result, 'ICAP%/1%.0 200 OK') then
        conn:add_write(icap_w_respond_cb, respond_request)
      else
        lua_util.debugm(N, task, '%s: OPTIONS: No OK in return: |%s|', rule.log_prefix, string.gsub(result, "\r\n", ""))
      end
    end

    local function icap_callback(err, conn)

      if err then

          -- set current upstream to fail because an error occurred
          upstream:fail()

          -- retry with another upstream until retransmits exceeds
          if retransmits > 0 then

            retransmits = retransmits - 1

            -- Select a different upstream!
            upstream = rule.upstreams:get_upstream_round_robin()
            addr = upstream:get_addr()

            lua_util.debugm(N, task, '%s: retry IP: %s:%s err: %s', rule.log_prefix, addr, addr:get_port(), err)

            tcp.request({
              task = task,
              host = addr:to_string(),
              port = addr:get_port(),
              timeout = rule['timeout'],
              stop_pattern = '\r\n',
              data = options_request,
              read = false,
              callback = icap_callback,
            })
          else
            rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits exceed', rule['symbol'], rule['type'])
            task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and retransmits exceed')
          end
      else
        --lua_util.debugm(N, task, '%s: connect result: |%s|', rule.log_prefix, conn)
        conn:add_read(icap_r_options_cb, '\r\n\r\n')
        --lua_util.debugm(N, task, '%s: icap_w_options_cb: |%s|%s|', rule.log_prefix, err, conn)

        -- set upstream ok
        if upstream then upstream:ok() end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      stop_pattern = '\r\n',
      data = options_request,
      read = false,
      callback = icap_callback,
    })

    --lua_util.debugm(N, task, '%s: after request: |%s|', rule['symbol'], rule['type'])
  end
  if need_av_check(task, content, rule) then
    if check_av_cache(task, digest, rule, icap_check_uncached) then
      return
    else
      icap_check_uncached()
    end
  end
end


local av_types = {
  clamav = {
    configure = clamav_config,
    check = clamav_check
  },
  fprot = {
    configure = fprot_config,
    check = fprot_check
  },
  sophos = {
    configure = sophos_config,
    check = sophos_check
  },
  savapi = {
    configure = savapi_config,
    check = savapi_check
  },
  kaspersky = {
    configure = kaspersky_config,
    check = kaspersky_check
  },
  dcc = {
    configure = dcc_config,
    check = dcc_check
  },
  pyzor = {
    configure = pyzor_config,
    check = pyzor_check
  },
  oletools = {
    configure = oletools_config,
    check = oletools_check
  },
  razor = {
    configure = razor_config,
    check = razor_check
  },
  spamassassin = {
    configure = spamassassin_config,
    check = spamassassin_check
  },
  icap = {
    configure = icap_config,
    check = icap_check
  },
}

local function add_external_services_rule(sym, opts)
  if not opts['type'] then
    rspamd_logger.errx(rspamd_config, 'unknown type for AV rule %s', sym)
    return nil
  end

  if not opts['symbol'] then opts['symbol'] = sym:upper() end
  local cfg = av_types[opts['type']]

  if not opts['symbol_fail'] then
    opts['symbol_fail'] = string.upper(opts['type']) .. '_FAIL'
  end

  -- WORKAROUND for deprecated attachments_only
  if opts['attachments_only'] ~= nil then
    opts['scan_mime_parts'] = opts['attachments_only']
    rspamd_logger.warnx(rspamd_config, '%s: Using attachments_only is deprecated. '..
     'Please use scan_mime_parts = %s instead', opts['symbol'], opts['type'], opts['attachments_only'])
  end
  -- WORKAROUND for deprecated attachments_only

  if not cfg then
    rspamd_logger.errx(rspamd_config, 'unknown external-services type: %s',
      opts['type'])
  end

  local rule = cfg.configure(opts)
  rule.type = opts.type
  rule.symbol_fail = opts.symbol_fail


  if not rule then
    rspamd_logger.errx(rspamd_config, 'cannot configure %s for %s',
      opts['type'], opts['symbol'])
    return nil
  end

  local function create_regex_table(task, patterns)
    local regex_table = {}
    if patterns[1] then
      for i, p in ipairs(patterns) do
        if type(p) == 'table' then
          local new_set = {}
          for k, v in pairs(p) do
            new_set[k] = rspamd_regexp.create_cached(v)
          end
          regex_table[i] = new_set
        else
          regex_table[i] = {}
        end
      end
    else
      for k, v in pairs(patterns) do
        regex_table[k] = rspamd_regexp.create_cached(v)
      end
    end
    return regex_table
  end

  if opts['mime_parts_filter_regex'] ~= nil
    or opts['mime_parts_filter_ext'] ~= nil then
      rule.scan_all_mime_parts = false
  end

  rule['patterns'] = create_regex_table(task, opts['patterns'] or {})

  rule['mime_parts_filter_regex'] = create_regex_table(task, opts['mime_parts_filter_regex'] or {})

  rule['mime_parts_filter_ext'] = create_regex_table(task, opts['mime_parts_filter_ext'] or {})

  if opts['whitelist'] then
    rule['whitelist'] = rspamd_config:add_hash_map(opts['whitelist'])
  end

  local function match_filter(task, found, patterns)
    if type(patterns) ~= 'table' then
      lua_util.debugm(N, task, '%s: pattern not table %s', rule.log_prefix, type(patterns))
      return false
    end
    if not patterns[1] then
      --lua_util.debugm(N, task, '%s: in not pattern[1]', rule['symbol'], rule['type'])
      for _, pat in pairs(patterns) do
        if pat:match(found) then
          return true
        end
      end
      return false
    else
      for _, p in ipairs(patterns) do
        for _, pat in ipairs(p) do
          if pat:match(found) then
            return true
          end
        end
      end
      return false
    end
  end

  -- borrowed from mime_types.lua
  -- ext is the last extension, LOWERCASED
  -- ext2 is the one before last extension LOWERCASED
  local function gen_extension(fname)
    local filename_parts = rspamd_str_split(fname, '.')

    local ext = {}
    for n = 1, 2 do
        ext[n] = #filename_parts > n and string.lower(filename_parts[#filename_parts + 1 - n]) or nil
    end
  --lua_util.debugm(N, task, '%s: extension found: %s', rule.log_prefix, ext[1])
    return ext[1],ext[2],filename_parts
  end

  return function(task)
    if rule.scan_mime_parts then
      local parts = task:get_parts() or {}

      local filter_func = function(p)
        local content_type,content_subtype = p:get_type()
        local fname = p:get_filename()
        local ext,ext2,part_table
        local extension_check = false
        local content_type_check = false
        --lua_util.debugm(N, task, '%s: mime_parts_filter_ext: %s', rule.log_prefix, rule['mime_parts_filter_ext'])
        --lua_util.debugm(N, task, '%s: mime_parts_filter_regex: %s', rule.log_prefix, rule['mime_parts_filter_regex'])
        --lua_util.debugm(N, task, '%s: fname: %s', rule.log_prefix, fname)
        if fname ~= nil then
          --lua_util.debugm(N, task, '%s: fname not nil - %s', rule.log_prefix, fname)
          --lua_util.debugm(N, task, '%s: fname not nil match - %s', rule.log_prefix, match_filter(task, fname, rule['mime_parts_filter_regex']))
          ext,ext2,part_table = gen_extension(fname)
          lua_util.debugm(N, task, '%s: extension found: %s - 2.ext: %s - parts: %s', rule.log_prefix, ext, ext2, part_table)
          if match_filter(task, ext, rule['mime_parts_filter_ext']) or match_filter(task, ext2, rule['mime_parts_filter_ext']) then
            lua_util.debugm(N, task, '%s: extension matched: %s', rule.log_prefix, ext)
            extension_check = true
          end
          if match_filter(task, fname, rule['mime_parts_filter_regex']) then
            --lua_util.debugm(N, task, '%s: regex fname: %s', rule.log_prefix, fname)
            content_type_check = true
          end
        end
        if content_type ~=nil and content_subtype ~= nil then
          if match_filter(task, content_type..'/'..content_subtype, rule['mime_parts_filter_regex']) then
            lua_util.debugm(N, task, '%s: regex ct: %s', rule.log_prefix, content_type..'/'..content_subtype)
            content_type_check = true
          end
        end

        return (rule.scan_image_mime and p:is_image())
            or (rule.scan_text_mime and p:is_text())
            or (p:get_filename() and rule.scan_all_mime_parts ~= false)
            or extension_check
            or content_type_check
      end

      fun.each(function(p)
        local content = p:get_content()
        --local length = p:get_raw_length()
        --lua_util.debugm(N, task, '%s: mime_part length : %s', rule.log_prefix, length)
        if content and #content > 0 then
          cfg.check(task, content, p:get_digest(), rule)
        end
      end, fun.filter(filter_func, parts))

    else
      cfg.check(task, task:get_content(), task:get_digest(), rule)
    end
  end
end

-- Registration
local opts = rspamd_config:get_all_opt('external-services')
if opts and type(opts) == 'table' then
  redis_params = rspamd_parse_redis_server('external-services')
  local has_valid = false
  for k, m in pairs(opts) do
    if type(m) == 'table' and m.servers then
      if not m.type then m.type = k end
      if not m.name then m.name = k end
      local cb = add_external_services_rule(k, m)

      if not cb then
        rspamd_logger.errx(rspamd_config, 'cannot add rule: "' .. k .. '"')
      else
        local id = rspamd_config:register_symbol({
          type = 'normal',
          name = m['symbol'],
          callback = cb,
          score = 0.0,
          group = 'external-services'
        })
        rspamd_config:register_symbol({
          type = 'virtual',
          name = m['symbol_fail'],
          parent = id,
          score = 0.0,
          group = 'external-services'
        })
        has_valid = true
        if type(m['patterns']) == 'table' then
          if m['patterns'][1] then
            for _, p in ipairs(m['patterns']) do
              if type(p) == 'table' then
                for sym in pairs(p) do
                  lua_util.debugm(N, rspamd_config, 'registering: %1', {
                    type = 'virtual',
                    name = sym,
                    parent = m['symbol'],
                    parent_id = id,
                  })
                  rspamd_config:register_symbol({
                    type = 'virtual',
                    name = sym,
                    parent = id
                  })
                end
              end
            end
          else
            for sym in pairs(m['patterns']) do
              rspamd_config:register_symbol({
                type = 'virtual',
                name = sym,
                parent = id
              })
            end
          end
        end
        if m['score'] then
          -- Register metric symbol
          local description = 'external-services symbol'
          local group = 'external-services'
          if m['description'] then
            description = m['description']
          end
          if m['group'] then
            group = m['group']
          end
          rspamd_config:set_metric_symbol({
            name = m['symbol'],
            score = m['score'],
            description = description,
            group = group or 'external-services'
          })
        end
      end
    end
  end

  if not has_valid then
    lua_util.disable_module(N, 'config')
  end
end
