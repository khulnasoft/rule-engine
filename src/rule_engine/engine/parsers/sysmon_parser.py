import os
import xml.etree.ElementTree as ET
from rule_engine.engine.categories import classify_rule
from rule_engine.engine.models import RuleFormat

NS = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_sysmon_rule(file_path):
    if os.path.isdir(file_path):
        rules = []
        for root, _, files in os.walk(file_path):
            for f in files:
                if f.endswith(".xml", ".evtx"):
                    parsed = parse_sysmon_file(os.path.join(root, f))
                    if isinstance(parsed, list):
                        rules.extend(parsed)
                    else:
                        rules.append(parsed)
        if not rules:
            raise ValueError(f"No Sysmon rules found in {file_path}")
        return rules
    return parse_sysmon_file(file_path)


def parse_sysmon_file(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    rules = []
    for query in root.findall(".//ev:Query", NS) or root.findall(".//Query"):
        rule = _parse_query(query)
        if rule:
            rule = classify_rule(rule)
            rules.append(rule)
    if not rules:
        rule = _parse_fallback(root)
        if rule:
            rules.append(rule)
    if not rules:
        raise ValueError(f"Invalid Sysmon rule file: {file_path}")
    return rules if len(rules) > 1 else rules[0]


def _parse_query(query_elem):
    event_id = _extract_event_id(query_elem)
    select = query_elem.find("ev:Select", NS) or query_elem.find("Select")
    select_text = select.text if select is not None else ""
    match_on = query_elem.find("ev:MatchOn", NS) or query_elem.find("MatchOn")
    fields = _extract_match_fields(match_on)
    description = _extract_description(query_elem)
    name = _extract_name(query_elem, event_id)
    rule = {
        "name": name,
        "format": "sysmon",
        "description": description or f"Sysmon Event {event_id}" if event_id else "Sysmon rule",
        "level": 0,
        "event_id": event_id,
        "select": select_text,
        "fields": fields,
        "metadata": {
            "name": name,
            "event_id": event_id,
            "select": select_text,
        },
        "detection": {
            "select": select_text,
            "fields": fields,
        },
        "condition": select_text,
    }
    return rule


def _extract_event_id(query_elem):
    for path in ["ev:Select", "Select"]:
        select = query_elem.find(path, NS) if "ev:" in path else query_elem.find(path)
        if select is not None and select.text:
            text = select.text
            parts = text.split(")")
            for part in parts:
                if "EventID" in part:
                    if "=" in part:
                        return part.split("=")[-1].strip()
                    if "]" in part:
                        return part.split("]")[0].split("(")[-1].strip()
    select = query_elem.find("ev:Select", NS) or query_elem.find("Select")
    if select is not None and select.text:
        text = select.text
        for part in text.split(")"):
            if "EventID" in part:
                if "=" in part:
                    return part.split("=")[-1].strip()
                if "]" in part:
                    return part.split("]")[0].split("(")[-1].strip()
    return None


def _extract_match_fields(match_on_elem):
    fields = {}
    if match_on_elem is None:
        return fields
    for child in match_on_elem:
        tag = child.tag
        if "}" in tag:
            tag = tag.split("}", 1)[1]
        local_name = child.attrib.get("Name", child.attrib.get("Name", ""))
        if local_name:
            fields[local_name] = child.text or ""
        else:
            fields[tag] = child.text or ""
    return fields


def _extract_description(query_elem):
    for path in ["ev:Description", "Description"]:
        desc = query_elem.find(path, NS) if "ev:" in path else query_elem.find(path)
        if desc is not None and desc.text:
            return desc.text
    for child in query_elem.iter():
        tag = child.tag
        if "}" in tag:
            tag = tag.split("}", 1)[1]
        if tag == "Description" and child.text:
            return child.text
    return None


def _extract_name(query_elem, event_id):
    desc = _extract_description(query_elem)
    if desc:
        return desc
    return f"Sysmon Event {event_id}" if event_id else "Sysmon rule"


def _parse_fallback(root):
    rule = {
        "name": "Sysmon rule",
        "format": "sysmon",
        "description": "Sysmon rule",
        "level": 0,
        "metadata": {},
        "detection": {},
        "condition": "",
    }
    return rule


def load_sysmon_rule(file_path):
    return parse_sysmon_rule(file_path)
