import re
from rule_engine.engine.categories import classify_rule

YARA_CATEGORY_TO_SYSMON_EVENT = {
    "execution": "1",
    "process_creation": "1",
    "persistence": "1",
    "privilege-escalation": "1",
    "defense-evasion": "1",
    "discovery": "1",
    "lateral-movement": "3",
    "command-and-control": "3",
    "exfiltration": "3",
    "network_connection": "3",
    "credential-access": "1",
    "impact": "1",
    "ransomware": "1",
    "malware": "1",
    "packers": "1",
    "webshells": "1",
    "malicious-documents": "11",
    "file_creation": "11",
    "crypto": "1",
    "exploit-kits": "1",
    "anti-debug-anti-vm": "1",
    "threat-intelligence": "1",
    "indicators-of-compromise": "1",
    "living-off-the-land": "1",
    "vulnerability-scanning": "1",
    "phishing": "1",
    "deprecated": "1",
    "capabilities": "1",
    "cve-rules": "1",
}

YARA_KEYWORD_TO_SYSMON_EVENT = {
    "process": "1",
    "createprocess": "1",
    "createremote": "8",
    "driver": "6",
    "file": "11",
    "network": "3",
    "registry": "12",
    "connection": "3",
    "dns": "22",
    "http": "3",
    "tcp": "3",
    "udp": "3",
    "thread": "8",
    "memory": "10",
}


def convert_yara_to_sysmon(yara_rule):
    if isinstance(yara_rule, str):
        raise ValueError("YARA to Sysmon conversion requires a parsed rule dict, not a string. Use parse_yara_rule_string first.")
    if not yara_rule or not isinstance(yara_rule, dict):
        raise ValueError("Invalid YARA rule: must be a non-empty dictionary")

    name = yara_rule.get("name", "YaraRule")
    strings = yara_rule.get("strings", [])
    condition = yara_rule.get("condition", "")
    meta = yara_rule.get("meta", {})
    tags = yara_rule.get("tags", [])
    category = (yara_rule.get("primary_category")
            or yara_rule.get("categories", [""])[0]
            or (yara_rule.get("meta", {}) or {}).get("category", ""))

    event_id = _determine_event_id(name, condition, meta, tags, category)
    sysmon_fields = _build_sysmon_fields(strings)
    select = _build_select(event_id)

    description = f"YARA → Sysmon Event {event_id}: {name}"

    rule_dict = {
        "name": description,
        "format": "sysmon",
        "description": description,
        "level": 0,
        "event_id": event_id,
        "select": select,
        "fields": sysmon_fields,
        "metadata": {
            "name": description,
            "event_id": event_id,
            "source_format": "yara",
            "yara_condition": condition,
            "yara_category": category,
            "yara_tags": tags,
        },
        "detection": {
            "select": select,
            "fields": sysmon_fields,
        },
        "condition": select,
    }

    return classify_rule(rule_dict)


def _determine_event_id(name, condition, meta, tags, category):
    if meta and isinstance(meta, dict):
        event_id = meta.get("event_id") or meta.get("sysmon_event_id")
        if event_id:
            return str(event_id)

    if category in YARA_CATEGORY_TO_SYSMON_EVENT:
        return YARA_CATEGORY_TO_SYSMON_EVENT[category]

    for tag in tags:
        tag_str = str(tag).lower()
        for keyword, eid in YARA_KEYWORD_TO_SYSMON_EVENT.items():
            if keyword in tag_str:
                return eid

    condition_lower = condition.lower()
    for keyword, eid in YARA_KEYWORD_TO_SYSMON_EVENT.items():
        if keyword in condition_lower:
            return eid

    return "1"


def _build_sysmon_fields(strings):
    fields = {}
    hex_patterns = []
    for string_value in strings:
        if _is_hex_string(string_value):
            cleaned = re.sub(r'\s+', '', string_value)
            hex_patterns.append(cleaned)
        else:
            if "CommandLine" not in fields:
                fields["CommandLine"] = string_value
            elif "Image" not in fields:
                fields["Image"] = string_value
            elif "Description" not in fields:
                fields["Description"] = string_value
    if hex_patterns:
        fields["HexPattern"] = "".join(hex_patterns)
    return fields


def _is_hex_string(s):
    cleaned = re.sub(r'\s+', '', s)
    return bool(re.match(r'^[0-9a-fA-F?]+$', cleaned)) and len(cleaned) >= 4


def _build_select(event_id):
    return f"*[System[(EventID={event_id})]]"
