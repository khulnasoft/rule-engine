import xml.etree.ElementTree as ET


def convert_wazuh_to_yara(wazuh_rule):
    """Convert a Wazuh XML rule to YARA format."""
    rule_id = wazuh_rule.get('id', 'unknown')
    description = wazuh_rule.get('description', '')
    match_text = wazuh_rule.get('match', '') or wazuh_rule.get('regex', '') or wazuh_rule.get('if_sid', '')
    group = wazuh_rule.get('group', 'unknown')

    strings = []
    if match_text:
        strings.append(f'"{match_text}"')

    condition = 'all of them'
    if strings:
        condition = ' or '.join([f'$a{i}' for i in range(len(strings))])

    yara_rule = f"""rule wazuh_{rule_id} {{
    meta:
        description = "{description}"
        group = "{group}"
    strings:
"""
    for i, s in enumerate(strings):
        yara_rule += f'        $a{i} = {s}\n'

    yara_rule += f"""    condition:
        {condition}
}}"""
    return yara_rule


def load_wazuh_rule(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    return {
        'id': root.find('id').text if root.find('id') is not None else '',
        'level': root.find('level').text if root.find('level') is not None else '',
        'description': root.find('description').text if root.find('description') is not None else '',
        'group': root.find('group').text if root.find('group') is not None else '',
    }
