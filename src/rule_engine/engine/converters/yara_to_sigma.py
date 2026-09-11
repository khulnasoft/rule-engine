import yaml
import re


def convert_yara_to_sigma(yara_rule):
    """Convert a YARA rule to Sigma format."""
    sigma_rule = {
        'title': yara_rule.get('name', 'yara_rule'),
        'description': yara_rule.get('meta', {}).get('description', ''),
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection': {},
            'condition': yara_rule.get('condition', 'all of them')
        },
        'level': 'high',
        'id': 'yara_generated'
    }

    strings = yara_rule.get('strings', [])
    if strings:
        sigma_rule['detection']['selection'] = {'CommandLine': strings}

    imports = yara_rule.get('imports', [])
    if imports:
        sigma_rule['metadata'] = {'imports': imports}

    return sigma_rule


def load_yara_rule(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    rule = {}
    rule_name = re.search(r'rule\s+(\w+)', content)
    if rule_name:
        rule['name'] = rule_name.group(1)
    condition = re.search(r'condition:\s*(.+?)(?=\n\w|\Z)', content, re.DOTALL)
    if condition:
        rule['condition'] = condition.group(1).strip()
    rule['strings'] = []
    string_pattern = re.compile(r'\$[a-zA-Z0-9_]+\s*=\s*"(.*?)"')
    for match in string_pattern.finditer(content):
        rule['strings'].append(match.group(1))
    return rule
