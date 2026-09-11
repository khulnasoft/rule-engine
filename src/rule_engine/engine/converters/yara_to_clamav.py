import re
from rule_engine.engine.categories import classify_rule


def _extract_hex_strings(content):
    results = []
    pattern = re.compile(r'\$([a-zA-Z0-9_]+)\s*=\s*\{([^}]*)\}')
    for match in pattern.finditer(content):
        name = match.group(1)
        hex_content = match.group(2).strip()
        cleaned = re.sub(r'\s+', '', hex_content)
        results.append((name, cleaned))
    return results


def _extract_ascii_strings(content):
    results = []
    pattern = re.compile(r'\$([a-zA-Z0-9_]+)\s*=\s*"([^"]+)"')
    for match in pattern.finditer(content):
        name = match.group(1)
        string_value = match.group(2)
        results.append((name, string_value))
    return results


def _has_wide(content):
    return bool(re.search(r'\bwide\b', content))


def _has_nocase(content):
    return bool(re.search(r'\bnocase\b', content))


def _has_fullword(content):
    return bool(re.search(r'\bfullword\b', content))


def _is_hex_string(s):
    cleaned = re.sub(r'\s+', '', s)
    return bool(re.match(r'^[0-9a-fA-F?]+$', cleaned)) and len(cleaned) >= 4


def _build_clamav_signatures(yara_rule):
    signatures = []
    name = yara_rule.get("name", "YaraRule")
    strings = yara_rule.get("strings", [])
    condition = yara_rule.get("condition", "")

    wide = bool(re.search(r'\bwide\b', condition))
    nocase = bool(re.search(r'\bnocase\b', condition))
    fullword = bool(re.search(r'\bfullword\b', condition))

    searchable_strings = []

    for string_value in strings:
        if _is_hex_string(string_value):
            cleaned = re.sub(r'\s+', '', string_value)
            if cleaned:
                sig_name = f"{name}_{_sanitize_name(string_value[:20])}"
                info = f"yara_hex:{string_value[:50]}"
                signatures.append(f"{sig_name};3;{cleaned};{info};")
                searchable_strings.append(string_value)
        else:
            sig_name = f"{name}_{_sanitize_name(string_value[:30])}"
            encoding = ""
            if wide:
                encoding = "_wide"
            if nocase:
                encoding += "_nocase"
            if fullword:
                encoding += "_fullword"
            info = f"yara_ascii:{string_value[:50]}"
            pattern = string_value.replace("\\", "\\\\").replace(";", "\\;")
            signatures.append(f"{sig_name}{encoding};0;{pattern};{info};")
            searchable_strings.append(string_value)

    return signatures, searchable_strings, wide, nocase, fullword


def _sanitize_name(raw):
    return re.sub(r'[^a-zA-Z0-9_]', '_', raw)[:30]


def convert_yara_to_clamav(yara_rule):
    if isinstance(yara_rule, str):
        raise ValueError("YARA to ClamAV conversion requires a parsed rule dict, not a string. Use parse_yara_rule_string first.")
    if not yara_rule or not isinstance(yara_rule, dict):
        raise ValueError("Invalid YARA rule: must be a non-empty dictionary")

    name = yara_rule.get("name", "YaraRule")
    signatures, searchable_strings, wide, nocase, fullword = _build_clamav_signatures(yara_rule)

    if not signatures:
        raise ValueError(f"No convertible strings found in YARA rule: {name}")

    clamav_content = "\n".join(signatures)

    rule_dict = {
        "name": name,
        "format": "clamav",
        "description": f"ClamAV signatures converted from YARA rule: {name}. {' '.join(searchable_strings)}",
        "level": 0,
        "clamav_type": "multi-signature",
        "clamav_signatures": signatures,
        "metadata": {
            "name": name,
            "source_format": "yara",
            "yara_condition": yara_rule.get("condition", ""),
            "wide": wide,
            "nocase": nocase,
        },
        "detection": {
            "signatures": signatures,
        },
        "condition": ";".join(signatures),
    }

    return classify_rule(rule_dict)
