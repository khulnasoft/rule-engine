import os
from rule_engine.engine.categories import classify_rule
from rule_engine.engine.models import RuleFormat


CLAMAV_TYPE_NAMES = {
    0: "normal",
    1: "archive",
    2: "ole2",
    3: "pe",
    4: "email",
    5: "document",
}


def parse_clamav_rule(file_path):
    if os.path.isdir(file_path):
        rules = []
        for root, _, files in os.walk(file_path):
            for f in files:
                if f.endswith((".ndb", ".hdb")):
                    rules.extend(parse_clamav_file(os.path.join(root, f)))
        if not rules:
            raise ValueError(f"No ClamAV signatures found in {file_path}")
        return rules
    return parse_clamav_file(file_path)


def parse_clamav_file(file_path):
    rules = []
    with open(file_path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rule = _parse_signature_line(line)
            if rule:
                rule = classify_rule(rule)
                rules.append(rule)
    if not rules:
        raise ValueError(f"Invalid ClamAV rule file: {file_path}")
    return rules if len(rules) > 1 else rules[0]


def _parse_signature_line(line):
    parts = line.rstrip(";").split(";")
    if len(parts) < 3:
        return None
    name = parts[0].strip()
    type_code = parts[1].strip()
    pattern = parts[2].strip()
    info = parts[3].strip() if len(parts) > 3 else ""
    try:
        type_num = int(type_code)
    except ValueError:
        type_num = 0
    type_name = CLAMAV_TYPE_NAMES.get(type_num, "unknown")
    rule = {
        "name": name,
        "format": "clamav",
        "description": f"ClamAV {type_name} signature: {name}",
        "level": 0,
        "clamav_type": type_name,
        "clamav_type_code": type_num,
        "pattern": pattern,
        "info": info,
        "metadata": {
            "name": name,
            "type": type_name,
            "info": info,
        },
        "detection": {
            "pattern": pattern,
            "type": type_name,
        },
        "condition": pattern,
    }
    if name.lower().startswith("win."):
        rule["metadata"]["platform"] = "windows"
    elif name.lower().startswith("linux."):
        rule["metadata"]["platform"] = "linux"
    elif name.lower().startswith("mac."):
        rule["metadata"]["platform"] = "macos"
    return rule


def load_clamav_rule(file_path):
    return parse_clamav_rule(file_path)
