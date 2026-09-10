import xml.etree.ElementTree as ET


def parse_wazuh_rule(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    rules = []
    for rule_elem in root.findall('.//rule'):
        rule = {}
        rule['id'] = rule_elem.get('id')
        rule['level'] = rule_elem.get('level')
        rule['description'] = _safe_text(rule_elem, 'description')
        rule['group'] = rule_elem.get('group') or _safe_text(rule_elem, 'group')
        rule['if_sid'] = rule_elem.get('if_sid') or _safe_text(rule_elem, 'if_sid')
        rule['if_group'] = rule_elem.get('if_group') or _safe_text(rule_elem, 'if_group')
        rule['if_matched_group'] = _safe_text(rule_elem, 'if_matched_group')
        rule['match'] = _safe_text(rule_elem, 'match')
        rule['regex'] = _safe_text(rule_elem, 'regex')
        rule['frequency'] = _safe_text(rule_elem, 'frequency')
        rule['timeframe'] = _safe_text(rule_elem, 'timeframe')
        rule['mitre'] = _extract_mitre(rule_elem)
        rule['options'] = _extract_options(rule_elem)
        rule['fields'] = _extract_fields(rule_elem)
        rule['group_attr'] = rule_elem.get('group')

        if not validate_wazuh_rule(rule):
            continue

        rules.append(rule)

    if not rules:
        raise ValueError(f"Invalid Wazuh rule: {file_path}")

    return rules[0]


def _safe_text(element, tag):
    elem = element.find(tag)
    return elem.text if elem is not None else None


def _extract_mitre(element):
    mitre_elem = element.find('mitre')
    if mitre_elem is not None:
        return {child.tag: child.text for child in mitre_elem}
    return None


def _extract_options(element):
    options_elem = element.find('options')
    if options_elem is not None:
        return {child.tag: child.text for child in options_elem}
    return None


def _extract_fields(element):
    fields = {}
    for field_elem in element.findall('field'):
        fields[field_elem.get('name', '')] = field_elem.text
    return fields


def validate_wazuh_rule(rule):
    required_fields = ['id', 'level', 'description']
    for field in required_fields:
        if field not in rule or rule[field] is None:
            print(f"Error: Missing required field '{field}' in Wazuh rule.")
            return False
    return True


def load_wazuh_rule(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    rules = []
    for rule_elem in root.findall('.//rule'):
        rules.append({
            'id': rule_elem.get('id'),
            'level': rule_elem.get('level'),
            'description': _safe_text(rule_elem, 'description'),
            'group': rule_elem.get('group'),
        })
    return rules[0] if len(rules) == 1 else rules
