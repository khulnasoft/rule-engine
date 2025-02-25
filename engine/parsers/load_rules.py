import yaml
import xml.etree.ElementTree as ET
import os
from engine.parsers.sigma_parser import parse_sigma_rule
from engine.parsers.wazuh_parser import parse_wazuh_rule

def load_yaml_rule(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def load_xml_rule(file_path):
    tree = ET.parse(file_path)
    return tree.getroot()

def validate_rule(rule):
    # Add validation logic here (check required fields, format, etc.)
    pass

def load_rule(file_path):
    _, ext = os.path.splitext(file_path)
    if ext == '.yml' or ext == '.yaml':
        return load_yaml_rule(file_path)
    elif ext == '.xml':
        return load_xml_rule(file_path)
    else:
        raise ValueError("Unsupported rule format")

def load_rule(file_path):
    """Load and validate a rule based on its format (YAML/JSON)."""
    _, ext = os.path.splitext(file_path)
    
    if ext in ['.yml', '.yaml']:
        return parse_sigma_rule(file_path)  # Parse Sigma rules (YAML format)
    
    elif ext == '.xml':
        return parse_wazuh_rule(file_path)  # Parse Wazuh rules (XML format)
    
    else:
        raise ValueError(f"Unsupported rule format: {ext}")