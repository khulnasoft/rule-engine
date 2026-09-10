import yaml
import xml.etree.ElementTree as ET
import os
import re
from rule_engine.engine.parsers.sigma_parser import parse_sigma_rule
from rule_engine.engine.parsers.wazuh_parser import parse_wazuh_rule
from rule_engine.engine.parsers.yara_parser import parse_yara_rule
from rule_engine.engine.models import RuleFormat


def load_yaml_rule(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)


def load_xml_rule(file_path):
    tree = ET.parse(file_path)
    return tree.getroot()


def validate_rule(rule, rule_format):
    pass


def load_rule(file_path):
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()
    if ext in ['.yaml', '.yml']:
        return parse_sigma_rule(file_path)
    elif ext == '.xml':
        return parse_wazuh_rule(file_path)
    elif ext in ['.yar', '.yara']:
        return parse_yara_rule(file_path)
    else:
        raise ValueError(f"Unsupported rule format: {ext}")


def load_rules_from_directory(directory):
    rules = []
    for root, dirs, files in os.walk(directory):
        for f in files:
            file_path = os.path.join(root, f)
            try:
                rule = load_rule(file_path)
                if rule:
                    rules.append(rule)
            except (ValueError, Exception):
                pass
    return rules
