import xml.etree.ElementTree as ET


def convert_yara_to_wazuh(yara_rule):
    """Convert a YARA rule to Wazuh XML format."""
    name = yara_rule.get('name', 'yara_rule')
    strings = yara_rule.get('strings', [])
    condition = yara_rule.get('condition', '')

    match_content = ' '.join(strings) if strings else condition

    wazuh_xml = f"""<group>
    <id>{hash(name) % 100000}</id>
    <level>high</level>
    <description>{name}</description>
    <group>yara_converted</group>
    <classification>8</classification>
    <logsource>
        <category>process_creation</category>
        <product>windows</product>
    </logsource>
    <detection>
        <match>{match_content}</match>
    </detection>
</group>"""
    return wazuh_xml.strip()


def load_yara_rule(file_path):
    import re
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
