# rule-engine/engine/parsers/wazuh_parser.py
import xml.etree.ElementTree as ET

def parse_wazuh_rule(file_path):
    """Parse a Wazuh rule from an XML file."""
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    rule = {}
    
    # Extract essential fields (customize as needed)
    rule['id'] = root.find('id').text
    rule['level'] = root.find('level').text
    rule['description'] = root.find('description').text
    rule['group'] = root.find('group').text

    # Validate the rule
    if not validate_wazuh_rule(rule):
        raise ValueError(f"Invalid Wazuh rule: {file_path}")
    
    return rule

def validate_wazuh_rule(rule):
    """Validate the structure of a Wazuh rule."""
    required_fields = ['id', 'level', 'description', 'group']
    
    for field in required_fields:
        if field not in rule:
            print(f"Error: Missing required field '{field}' in Wazuh rule.")
            return False
    return True
