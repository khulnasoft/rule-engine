# rule-engine/engine/converters/yara_to_sigma.py

import re

def convert_yara_to_sigma(yara_rule_content):
    """Convert a YARA rule to Sigma format."""
    sigma_rule = {
        'title': extract_yara_name(yara_rule_content),
        'description': 'Converted from YARA rule',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection': {'CommandLine': extract_yara_strings(yara_rule_content)},
            'condition': 'all of them'
        },
        'level': 'high',
        'id': 'generated-id',
        'behaviorgroup': '5',
        'classification': '8'
    }
    return sigma_rule

def extract_yara_name(content):
    """Extract YARA rule name."""
    match = re.search(r'rule\s+(\w+)', content)
    return match.group(1) if match else "Unnamed Rule"

def extract_yara_strings(content):
    """Extract strings from YARA rule."""
    string_pattern = re.compile(r'\$[a-zA-Z0-9_]+\s*=\s*"(.*?)"')
    return [match.group(1) for match in string_pattern.finditer(content)]
