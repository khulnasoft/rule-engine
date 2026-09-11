import yaml
import re
from rule_engine.engine.categories import classify_rule

SIGMA_FIELD_OPERATORS = [
    "endswith", "contains", "all", "re", "startswith", "lessThan",
    "greaterThan", "lessThanOrEqual", "greaterThanOrEqual", "equals",
    "is", "isNot", "matches", "cidr", "in", "not",
]

SIGMA_VALID_LOGSOURCE_PRODUCTS = [
    "windows", "linux", "macos", "android", "ios", "network",
    "cloud", "aws", "gcp", "azure", "kubernetes", "generic",
]

SIGMA_VALID_LOGSOURCE_CATEGORIES = [
    "process_creation", "file_creation", "file_deletion", "network_connection",
    "process_terminated", "registry_add_delete", "registry_set",
    "registry_value_add", "registry_value_delete", "windows_service_create",
    "windows_service_modify", "driver_loaded", "image_loaded",
    "create_remote_thread", "rawaccessread", "process_access",
    "file_create", "wmi_activity", "dns_query", "file_delete",
    "clamav", "sysmon", "application", "security", "system",
    "certificate", "certificate_mac", "firewall", "proxy",
    "dhcp", "dns", "microsoft_edge", "powershell", "scheduled_task",
    "task", "script", "shell", "command_shell", "cmd",
    "interpreter", "python", "javascript", "vbscript", "macro",
    "persistence", "privilege_escalation", "defense_evasion",
    "discovery", "lateral_movement", "execution", "initial_access",
    "credential_access", "collection", "exfiltration", "command_and_control",
    "impact", "timeline", "file", "network", "registry", "service",
]

SIGMA_TIMELINE_FIELDS = [
    "EventID", "Provider_Name", "Provider_Guid", "Channel",
    "Computer", "User", "Domain", "LogonId",
    "IpAddress", "Port", "Protocol", "Hostname",
]


def parse_sigma_rule(file_path):
    with open(file_path, "r") as file:
        rule = yaml.safe_load(file)

    if not validate_sigma_rule(rule):
        raise ValueError(f"Invalid Sigma rule: {file_path}")

    return classify_rule(rule)


def validate_sigma_rule(rule):
    if not isinstance(rule, dict):
        print("Error: Sigma rule must be a dictionary.")
        return False

    required_fields = ["title", "description", "logsource", "detection", "level"]
    for field in required_fields:
        if field not in rule or rule[field] is None:
            print(f"Error: Missing required field '{field}' in Sigma rule.")
            return False

    if not _validate_logsource(rule.get("logsource", {})):
        return False

    if not _validate_detection(rule.get("detection", {})):
        return False

    if not _validate_level(rule.get("level")):
        return False

    return True


def _validate_logsource(logsource):
    if not isinstance(logsource, dict):
        print("Error: 'logsource' must be a dictionary.")
        return False

    product = logsource.get("product")
    category = logsource.get("category")
    service = logsource.get("service")

    if product and product not in SIGMA_VALID_LOGSOURCE_PRODUCTS:
        print(f"Warning: Unrecognized logsource product '{product}'.")

    if category and category not in SIGMA_VALID_LOGSOURCE_CATEGORIES:
        print(f"Warning: Unrecognized logsource category '{category}'.")

    return True


def _validate_detection(detection):
    if not isinstance(detection, dict):
        print("Error: 'detection' must be a dictionary.")
        return False

    if "selection" not in detection and "condition" not in detection:
        print("Error: Detection must have 'selection' or 'condition'.")
        return False

    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, dict):
            for field, field_value in value.items():
                _validate_field_operators(field, field_value)

    return True


def _validate_field_operators(field, value):
    for op in SIGMA_FIELD_OPERATORS:
        if f"{field}|{op}" in field or f"{field}:{op}" in field:
            return True
    if isinstance(value, list):
        return True
    return False


def _validate_level(level):
    if level is None:
        return False
    valid_levels = ["low", "medium", "high", "critical", "informational"]
    if isinstance(level, str) and level.lower() not in valid_levels:
        print(f"Warning: Unrecognized level '{level}'.")
    return True


def has_timeline_fields(detection):
    if not isinstance(detection, dict):
        return False
    selection = detection.get("selection", {})
    if isinstance(selection, dict):
        for field in selection:
            if field in SIGMA_TIMELINE_FIELDS:
                return True
    return False


def detect_timeline(detection):
    return {
        "has_timeline": has_timeline_fields(detection),
        "fields": [f for f in SIGMA_TIMELINE_FIELDS if isinstance(detection.get("selection", {}), dict) and f in detection["selection"]],
    }


def load_sigma_rule(file_path):
    with open(file_path, "r") as file:
        return yaml.safe_load(file)
