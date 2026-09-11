import binascii
import re
from rule_engine.engine.models import Rule, RuleFormat


def match_rule(rule, event):
    if isinstance(rule, dict):
        fmt = rule.get("format", "sigma")
    elif isinstance(rule, Rule):
        fmt = rule.format.value
    else:
        return False

    if fmt == "yara":
        strings = rule.get("strings", []) if isinstance(rule, dict) else rule.strings
        for s in strings:
            if s in event:
                return True
        return False
    elif fmt == "sigma":
        detection = rule.get("detection", {}) if isinstance(rule, dict) else rule.detection
        selection = detection.get("selection", {}) if isinstance(rule, dict) else detection.get("selection", {})
        for field, value in selection.items():
            if isinstance(rule, dict) and field in event and str(value) in event:
                return True
            elif not isinstance(rule, dict) and field in event:
                return True
        return False
    elif fmt == "wazuh":
        if_sid = rule.get("if_sid") if isinstance(rule, dict) else rule.if_sid
        if_group = rule.get("if_group") if isinstance(rule, dict) else rule.if_group
        match_text = rule.get("match") if isinstance(rule, dict) else rule.match
        if if_sid and if_sid in event:
            return True
        if if_group and if_group in event:
            return True
        if match_text and match_text in event:
            return True
        return False
    elif fmt == "clamav":
        return _clamav_match(rule, event)
    elif fmt == "sysmon":
        return _sysmon_match(rule, event)
    return False


def _clamav_match(rule, event):
    pattern = rule.get("pattern", "") if isinstance(rule, dict) else rule.pattern
    clamav_type = rule.get("clamav_type", "normal") if isinstance(rule, dict) else rule.clamav_type

    if not pattern:
        return False

    if clamav_type in ("normal", "archive", "ole2", "email", "document", "unknown"):
        return pattern in event
    elif clamav_type == "pe":
        try:
            event_bytes = event.encode("utf-8", errors="ignore") if isinstance(event, str) else event
            pattern_bytes = binascii.unhexlify(pattern) if isinstance(pattern, str) else pattern
            return pattern_bytes in event_bytes
        except (ValueError, TypeError):
            return pattern in event
    return False


def _sysmon_match(rule, event):
    fields = rule.get("fields", {}) if isinstance(rule, dict) else rule.fields
    if not fields:
        return False
    for field, value in fields.items():
        if field in event and str(value) in event:
            return True
    return False


def execute_rules(rules, log_file):
    matched = []
    try:
        with open(log_file, "r") as f:
            for line in f:
                for rule in rules:
                    if match_rule(rule, line):
                        matched.append({"rule": rule.get("name", "unknown"), "line": line.strip()})
    except FileNotFoundError:
        pass
    return matched


class YaraExecutor:
    def match_rule(self, rule, event):
        strings = rule.get("strings", []) if isinstance(rule, dict) else rule.strings
        for s in strings:
            if s in event:
                return True
        return False

    def execute_rules(self, rules, log_file):
        matched = []
        with open(log_file, "r") as f:
            for line in f:
                for rule in rules:
                    if self.match_rule(rule, line):
                        matched.append({"rule": rule.get("name", "unknown"), "line": line.strip()})
        return matched


class SigmaExecutor:
    def match_rule(self, rule, event):
        detection = rule.get("detection", {}) if isinstance(rule, dict) else rule.detection
        selection = detection.get("selection", {}) if isinstance(rule, dict) else detection.get("selection", {})
        for field, value in selection.items():
            if isinstance(rule, dict) and field in event and str(value) in event:
                return True
            elif not isinstance(rule, dict) and field in event:
                return True
        return False

    def execute_rules(self, rules, log_file):
        matched = []
        with open(log_file, "r") as f:
            for line in f:
                for rule in rules:
                    if self.match_rule(rule, line):
                        matched.append({"rule": rule.get("name", "unknown"), "line": line.strip()})
        return matched


class WazuhExecutor:
    def match_rule(self, rule, event):
        if_sid = rule.get("if_sid") if isinstance(rule, dict) else rule.if_sid
        if_group = rule.get("if_group") if isinstance(rule, dict) else rule.if_group
        match_text = rule.get("match") if isinstance(rule, dict) else rule.match
        if if_sid and if_sid in event:
            return True
        if if_group and if_group in event:
            return True
        if match_text and match_text in event:
            return True
        return False

    def execute_rules(self, rules, log_file):
        matched = []
        with open(log_file, "r") as f:
            for line in f:
                for rule in rules:
                    if self.match_rule(rule, line):
                        matched.append({"rule": rule.get("name", "unknown"), "line": line.strip()})
        return matched


class ClamavExecutor:
    def match_rule(self, rule, event):
        return _clamav_match(rule, event)

    def execute_rules(self, rules, log_file):
        matched = []
        with open(log_file, "r") as f:
            for line in f:
                for rule in rules:
                    if self.match_rule(rule, line):
                        matched.append({"rule": rule.get("name", "unknown"), "line": line.strip()})
        return matched


class SysmonExecutor:
    def match_rule(self, rule, event):
        return _sysmon_match(rule, event)

    def execute_rules(self, rules, log_file):
        matched = []
        with open(log_file, "r") as f:
            for line in f:
                for rule in rules:
                    if self.match_rule(rule, line):
                        matched.append({"rule": rule.get("name", "unknown"), "line": line.strip()})
        return matched


def get_executor(fmt):
    if fmt == RuleFormat.YARA or fmt == "yara":
        return YaraExecutor()
    elif fmt == RuleFormat.SIGMA or fmt == "sigma":
        return SigmaExecutor()
    elif fmt == RuleFormat.WAZUH or fmt == "wazuh":
        return WazuhExecutor()
    elif fmt == RuleFormat.CLAMAV or fmt == "clamav":
        return ClamavExecutor()
    elif fmt == RuleFormat.SYSMON or fmt == "sysmon":
        return SysmonExecutor()
    raise ValueError(f"Unsupported rule format: {fmt}")
