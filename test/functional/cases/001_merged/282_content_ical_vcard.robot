*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${ICAL_ANOMALIES}   ${RSPAMD_TESTDIR}/messages/ical_anomalies.eml
${ICAL_CLEAN}       ${RSPAMD_TESTDIR}/messages/ical_clean.eml
${VCARD_ANOMALIES}  ${RSPAMD_TESTDIR}/messages/vcard_anomalies.eml
${VCARD_CLEAN}      ${RSPAMD_TESTDIR}/messages/vcard_clean.eml

${SETTINGS_ICAL}    {symbols_enabled = [ICAL_INVALID_PRODID, ICAL_INVALID_METHOD, ICAL_NUMERIC_LOCATION, ICAL_IMMEDIATE_ALARM]}
${SETTINGS_VCARD}   {symbols_enabled = [VCARD_INVALID_VERSION, VCARD_MISSING_FN]}

*** Test Cases ***
# An invite arrives as an inline text/calendar inside multipart/alternative,
# which is why lua_content does not gate calendar parts on is_attachment().
ICAL ANOMALIES
  Scan File  ${ICAL_ANOMALIES}  Settings=${SETTINGS_ICAL}
  Expect Symbol  ICAL_INVALID_PRODID
  Expect Symbol  ICAL_INVALID_METHOD
  Expect Symbol  ICAL_NUMERIC_LOCATION
  Expect Symbol  ICAL_IMMEDIATE_ALARM

ICAL CLEAN
  Scan File  ${ICAL_CLEAN}  Settings=${SETTINGS_ICAL}
  Do Not Expect Symbol  ICAL_INVALID_PRODID
  Do Not Expect Symbol  ICAL_INVALID_METHOD
  Do Not Expect Symbol  ICAL_NUMERIC_LOCATION
  Do Not Expect Symbol  ICAL_IMMEDIATE_ALARM

VCARD ANOMALIES
  Scan File  ${VCARD_ANOMALIES}  Settings=${SETTINGS_VCARD}
  Expect Symbol  VCARD_INVALID_VERSION
  Expect Symbol  VCARD_MISSING_FN

VCARD CLEAN
  Scan File  ${VCARD_CLEAN}  Settings=${SETTINGS_VCARD}
  Do Not Expect Symbol  VCARD_INVALID_VERSION
  Do Not Expect Symbol  VCARD_MISSING_FN
