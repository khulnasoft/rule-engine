# rule-engine/engine/parsers/yara_parser.py

import re

def parse_yara_rule(file_path):
    """Parse a YARA rule from a .yara file."""
    with open(file_path, 'r') as file:
        content = file.read()

    rule = {}

    # Extract rule name
    rule_name = re.search(r'rule\s+(\w+)', content)
    if rule_name:
        rule['name'] = rule_name.group(1)
    
    # Extract conditions (simplified, extend as needed)
    condition = re.search(r'condition:\s*(.*)', content, re.DOTALL)
    if condition:
        rule['condition'] = condition.group(1).strip()

    # Additional fields such as strings, metadata, etc., can be added here.
    rule['strings'] = extract_strings(content)

    # Validate rule
    if not validate_yara_rule(rule):
        raise ValueError(f"Invalid YARA rule: {file_path}")
    
    return rule

def extract_strings(content):
    """Extract the strings section from the YARA rule."""
    strings = []
    string_pattern = re.compile(r'\$[a-zA-Z0-9_]+\s*=\s*"(.*?)"')
    for match in string_pattern.finditer(content):
        strings.append(match.group(1))
    return strings

def validate_yara_rule(rule):
    """Validate the structure of a YARA rule."""
    if 'name' not in rule or 'condition' not in rule:
        print(f"Error: Missing required fields in YARA rule.")
        return False
    return True
