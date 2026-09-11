"""Canonical rule categories and deterministic metadata classification."""

import re
from typing import Any


CATEGORY_DEFINITIONS = {
    "anti-debug-anti-vm": "Anti-debug/Anti-VM",
    "capabilities": "Capabilities",
    "cve-rules": "CVE Rules",
    "crypto": "Crypto",
    "exploit-kits": "Exploit Kits",
    "malicious-documents": "Malicious Documents",
    "malware": "Malware",
    "packers": "Packers",
    "webshells": "WebShells",
    "deprecated": "Deprecated",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "execution": "Execution",
    "initial-access": "Initial Access",
    "lateral-movement": "Lateral Movement",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "ransomware": "Ransomware",
    "phishing": "Phishing",
    "vulnerability-scanning": "Vulnerability Scanning",
    "living-off-the-land": "Living off the Land",
    "indicators-of-compromise": "Indicators of Compromise",
    "threat-intelligence": "Threat Intelligence",
}


CATEGORY_ALIASES = {
    "anti-debug": "anti-debug-anti-vm",
    "anti-vm": "anti-debug-anti-vm",
    "antidebug-antivm": "anti-debug-anti-vm",
    "cve": "cve-rules",
    "cves": "cve-rules",
    "exploit-kit": "exploit-kits",
    "malicious-document": "malicious-documents",
    "web-shell": "webshells",
    "web_shell": "webshells",
    "webshell": "webshells",
    "c2": "command-and-control",
    "command-control": "command-and-control",
    "privilege_escalation": "privilege-escalation",
}


ATTACK_CATEGORY_MAP = {
    "persistence": "persistence",
    "privilege-escalation": "privilege-escalation",
    "defense-evasion": "defense-evasion",
    "credential-access": "credential-access",
    "discovery": "discovery",
    "execution": "execution",
    "initial-access": "initial-access",
    "lateral-movement": "lateral-movement",
    "command-and-control": "command-and-control",
    "exfiltration": "exfiltration",
    "impact": "impact",
}


def normalize_category(value: str) -> str:
    """Return the canonical slug for a category name or alias."""
    normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    normalized = CATEGORY_ALIASES.get(normalized, normalized)
    if normalized not in CATEGORY_DEFINITIONS:
        raise ValueError(f"Unknown rule category: {value}")
    return normalized


def list_categories() -> dict[str, str]:
    """Return a copy of the canonical category registry."""
    return CATEGORY_DEFINITIONS.copy()


def classify_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """Add normalized category, source, and CVE metadata to a rule mapping."""
    categories: list[str] = []
    sources: dict[str, list[str]] = {}

    def add_category(value: str, source: str) -> None:
        try:
            category = normalize_category(value)
        except (AttributeError, ValueError):
            return
        if category not in categories:
            categories.append(category)
        sources.setdefault(category, []).append(source)

    explicit_values = []
    for key in ("category", "primary_category", "categories"):
        value = rule.get(key)
        if isinstance(value, str):
            explicit_values.append(value)
        elif isinstance(value, (list, tuple, set)):
            explicit_values.extend(value)
    metadata = rule.get("meta") or rule.get("metadata") or {}
    if isinstance(metadata, dict):
        value = metadata.get("category") or metadata.get("categories")
        if isinstance(value, str):
            explicit_values.append(value)
        elif isinstance(value, (list, tuple, set)):
            explicit_values.extend(value)
    for value in explicit_values:
        add_category(value, "explicit")

    tags = rule.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    searchable_values = [str(rule.get(key, "")) for key in ("title", "name", "description")]
    searchable_values.extend(str(value) for value in tags)
    searchable_values.extend(str(value) for value in (rule.get("references") or []))
    searchable_text = " ".join(searchable_values)

    cves = sorted(set(re.findall(r"CVE[-_ ]?\d{4}[-_]\d{4,7}", searchable_text, re.IGNORECASE)))
    cves = [cve.upper().replace("_", "-").replace(" ", "-") for cve in cves]
    if cves:
        add_category("cve-rules", "cve")

    for tag in tags:
        tag_value = str(tag).lower()
        if tag_value.startswith("attack."):
            attack_name = tag_value.removeprefix("attack.").replace("_", "-")
            attack_category = ATTACK_CATEGORY_MAP.get(attack_name)
            if attack_category:
                add_category(attack_category, "attack-tag")

    keyword_categories = {
        "ransomware": ("ransomware",),
        "webshells": ("webshell", "web shell"),
        "packers": ("packer", "packed binary", "obfuscat"),
        "malicious-documents": ("malicious document", "weaponized document", "office macro"),
        "anti-debug-anti-vm": ("anti-debug", "anti-vm", "sandbox evasion"),
        "crypto": ("cryptominer", "cryptocurrency", "crypto mining"),
        "exploit-kits": ("exploit kit",),
    }
    for category, keywords in keyword_categories.items():
        if any(keyword in searchable_text.lower() for keyword in keywords):
            add_category(category, "content")

    result = dict(rule)
    result["categories"] = categories
    result["primary_category"] = categories[0] if categories else None
    result["category_source"] = sources
    result["cves"] = cves
    return result