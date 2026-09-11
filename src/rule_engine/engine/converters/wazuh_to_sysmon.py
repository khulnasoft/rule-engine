import re
import xml.etree.ElementTree as ET
from rule_engine.engine.categories import classify_rule


WAZUH_EVENT_GROUP_PATTERN = re.compile(r"sysmon_event(\d+)")
WAZUH_EVENT_DESC_PATTERN = re.compile(r"Sysmon\s*-\s*Event\s*(\d+)", re.IGNORECASE)

WAZUH_FIELD_TO_SYSMON = {
    "commandline": "CommandLine",
    "image": "Image",
    "targetimage": "TargetImage",
    "sourceimage": "SourceImage",
    "destinationimage": "DestinationImage",
    "user": "User",
    "description": "Description",
    "originalfilename": "OriginalFileName",
    "eventid": "EventID",
    "processguid": "ProcessGuid",
    "processid": "ProcessId",
    "fileversion": "FileVersion",
    "userguid": "UserGuid",
    "logonguid": "LogonGuid",
    "terminalSessionid": "TerminalSessionId",
    "integritylevel": "IntegrityLevel",
    "parentcommandline": "ParentCommandLine",
    "parentimage": "ParentImage",
    "parentprocessguid": "ParentProcessGuid",
    "parentprocessid": "ParentProcessId",
    "hash": "Hash",
    "signed": "Signed",
    "signature": "Signature",
    "signaturestatus": "SignatureStatus",
    "sourcehostname": "SourceHostname",
    "sourceport": "SourcePort",
    "destinationhostname": "DestinationHostname",
    "destinationport": "DestinationPort",
    "protocol": "Protocol",
    "initiated": "Initiated",
    "packetdir": "PacketDir",
    "ipversion": "IpVersion",
    "scopeid": "ScopeId",
}


def convert_wazuh_to_sysmon(wazuh_rule):
    if not wazuh_rule or not isinstance(wazuh_rule, dict):
        raise ValueError("Invalid Wazuh rule: must be a non-empty dictionary")

    description = wazuh_rule.get("description", "")
    event_id = _extract_event_id(description, wazuh_rule.get("group", ""))
    level = wazuh_rule.get("level", 0)
    match_text = wazuh_rule.get("match", "")
    regex = wazuh_rule.get("regex", "")
    fields = wazuh_rule.get("fields", {})
    if_sid = wazuh_rule.get("if_sid", "")
    if_group = wazuh_rule.get("if_group", "")

    sysmon_fields = {}
    for wazuh_field, value in fields.items():
        sysmon_name = WAZUH_FIELD_TO_SYSMON.get(wazuh_field.lower(), wazuh_field)
        sysmon_fields[sysmon_name] = value

    if match_text and "CommandLine" not in sysmon_fields:
        sysmon_fields["CommandLine"] = match_text
    if regex and "CommandLine" not in sysmon_fields:
        sysmon_fields["CommandLine"] = regex

    if not match_text and not regex and if_group:
        sysmon_fields["Group"] = if_group

    select = _build_select(event_id)
    description_sysmon = f"Sysmon Event {event_id}: {description}" if event_id else description

    rule_dict = {
        "name": description_sysmon,
        "format": "sysmon",
        "description": description_sysmon,
        "level": level,
        "event_id": event_id,
        "select": select,
        "fields": sysmon_fields,
        "metadata": {
            "name": description_sysmon,
            "event_id": event_id,
            "source_format": "wazuh",
            "original_if_sid": if_sid,
            "original_group": wazuh_rule.get("group", ""),
        },
        "detection": {
            "select": select,
            "fields": sysmon_fields,
        },
        "condition": select,
    }

    return classify_rule(rule_dict)


def _extract_event_id(description, group):
    match = WAZUH_EVENT_DESC_PATTERN.search(description)
    if match:
        return match.group(1)
    group_match = WAZUH_EVENT_GROUP_PATTERN.search(group)
    if group_match:
        return group_match.group(1)
    return "1"


def _build_select(event_id):
    return f"*[System[(EventID={event_id})]]"


def _build_match_on(fields):
    match_on = ""
    for name, value in fields.items():
        match_on += f'<Binary Name="{name}">{value}</Binary>'
    return match_on
