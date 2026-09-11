import yaml
import xml.etree.ElementTree as ET
import os
import re
from rule_engine.engine.parsers.sigma_parser import parse_sigma_rule
from rule_engine.engine.parsers.wazuh_parser import parse_wazuh_rule
from rule_engine.engine.parsers.yara_parser import parse_yara_rule
from rule_engine.engine.parsers.clamav_parser import parse_clamav_rule
from rule_engine.engine.parsers.sysmon_parser import parse_sysmon_rule
from rule_engine.engine.models import Rule, RuleFormat


def load_yaml_rule(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)


def load_xml_rule(file_path):
    tree = ET.parse(file_path)
    return tree.getroot()


def validate_rule(rule, rule_format):
    pass


def _is_sysmon_xml(file_path):
    if not os.path.exists(file_path):
        return False
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        for elem in root.iter():
            tag = elem.tag
            if "}" in tag:
                tag = tag.split("}", 1)[1]
            if tag == "QueryList":
                return True
    except (ET.ParseError, OSError):
        pass
    return False


def _detect_format(file_path, content=None):
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()
    if ext in ['.yaml', '.yml']:
        return RuleFormat.SIGMA
    elif ext == '.xml':
        if _is_sysmon_xml(file_path):
            return RuleFormat.SYSMON
        return RuleFormat.WAZUH
    elif ext in ['.yar', '.yara']:
        return RuleFormat.YARA
    elif ext in ['.ndb', '.hdb']:
        return RuleFormat.CLAMAV
    elif ext == '.evtx':
        return RuleFormat.SYSMON
    if content:
        if isinstance(content, str):
            if 'rule ' in content[:100] or 'meta:' in content[:200]:
                return RuleFormat.YARA
            if 'title:' in content[:200]:
                return RuleFormat.SIGMA
    return None


def load_rule(file_path):
    return RuleLoader().load(file_path)


def load_rules_from_directory(directory):
    return RuleLoader().load_directory(directory)


class RuleLoader:

    def __init__(self):
        self._parsers = {
            RuleFormat.YARA: parse_yara_rule,
            RuleFormat.SIGMA: parse_sigma_rule,
            RuleFormat.WAZUH: parse_wazuh_rule,
            RuleFormat.CLAMAV: parse_clamav_rule,
            RuleFormat.SYSMON: parse_sysmon_rule,
        }

    def detect_format(self, file_path, content=None):
        return _detect_format(file_path, content)

    def load(self, file_path, rule_format=None):
        if rule_format is None:
            rule_format = self.detect_format(file_path)
        if rule_format is None:
            raise ValueError(f"Cannot detect format for {file_path}")
        parser = self._parsers.get(rule_format)
        if parser is None:
            raise ValueError(f"Unsupported rule format: {rule_format.value}")
        return parser(file_path)

    def load_by_format(self, file_path, rule_format):
        return self.load(file_path, rule_format=rule_format)

    def load_directory(self, directory, rule_format=None):
        rules = []
        for root, dirs, files in os.walk(directory):
            for f in files:
                file_path = os.path.join(root, f)
                try:
                    rule = self.load(file_path) if rule_format is None else self.load_by_format(file_path, rule_format)
                    if rule:
                        rules.append(rule)
                except (ValueError, Exception):
                    pass
        return rules

    def validate(self, rule, rule_format):
        if rule_format == RuleFormat.SIGMA:
            from rule_engine.engine.parsers.sigma_parser import validate_sigma_rule
            return validate_sigma_rule(rule if isinstance(rule, dict) else rule.to_dict())
        return True
