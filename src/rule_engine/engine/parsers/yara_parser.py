import yaml
import xml.etree.ElementTree as ET
import re
from rule_engine.engine.categories import classify_rule


def parse_yara_rule(file_path):
    with open(file_path, 'r') as file:
        content = file.read()

    rule = {}

    rule_name = re.search(r'rule\s+(\w+)', content)
    if rule_name:
        rule['name'] = rule_name.group(1)

    condition = re.search(r'condition:\s*(.+?)(?=\n\w|\Z)', content, re.DOTALL)
    if condition:
        rule['condition'] = condition.group(1).strip()

    rule['strings'] = extract_strings(content)
    rule['imports'] = extract_imports(content)
    rule['meta'] = extract_meta(content)
    rule['filesize'] = extract_filesize(content)

    if not validate_yara_rule(rule):
        raise ValueError(f"Invalid YARA rule: {file_path}")

    return classify_rule(rule)


def extract_strings(content):
    strings = []
    string_pattern = re.compile(r'\$[a-zA-Z0-9_]+\s*=\s*"(.*?)"')
    for match in string_pattern.finditer(content):
        strings.append(match.group(1))
    hex_pattern = re.compile(r'\$[a-zA-Z0-9_]+\s*=\s*\{(.*?)\}')
    for match in hex_pattern.finditer(content):
        strings.append(match.group(1))
    return strings


def extract_imports(content):
    imports = []
    import_pattern = re.compile(r'import\s+"([^"]+)"')
    for match in import_pattern.finditer(content):
        imports.append(match.group(1))
    return imports


def extract_meta(content):
    meta = {}
    meta_pattern = re.compile(r'meta:\s*\n((?:\s+\w+\s*=\s*.+\n?)+)', re.DOTALL)
    match = meta_pattern.search(content)
    if match:
        for line in match.group(1).strip().split('\n'):
            if '=' in line:
                key, val = line.strip().split('=', 1)
                meta[key.strip()] = val.strip().strip('"').strip("'")
    return meta


def extract_filesize(content):
    filesize_match = re.search(r'filesize\s*([<>=!]=?\s*\d+[KMGT]?)', content)
    return filesize_match.group(1) if filesize_match else None


def parse_yara_rule_string(content):
    if isinstance(content, str):
        rule = {}
        rule_name = re.search(r'rule\s+(\w+)', content)
        if rule_name:
            rule['name'] = rule_name.group(1)
        condition = re.search(r'condition:\s*(.+?)(?=\n\w|\Z)', content, re.DOTALL)
        if condition:
            rule['condition'] = condition.group(1).strip()
        rule['strings'] = extract_strings(content)
        rule['imports'] = extract_imports(content)
        rule['meta'] = extract_meta(content)
        return classify_rule(rule)
    return content


def validate_yara_rule(rule):
    if 'name' not in rule or 'condition' not in rule:
        print(f"Error: Missing required fields in YARA rule.")
        return False
    return True


def load_sigma_rule(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)
