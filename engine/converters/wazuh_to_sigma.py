# rule-engine/engine/converters/wazuh_to_sigma.py

import xml.etree.ElementTree as ET

def convert_wazuh_to_sigma(wazuh_rule):
    """Convert a Wazuh XML rule to Sigma format."""
    sigma_rule = {
        'title': f'Wazuh rule {wazuh_rule["id"]}',
        'description': wazuh_rule['description'],
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection': {'CommandLine': [wazuh_rule.get('commandline', '')]},
            'condition': 'all of them'
        },
        'level': wazuh_rule['level'],
        'id': wazuh_rule['id'],
        'behaviorgroup': '5',
        'classification': '8'
    }
    return sigma_rule

def load_wazuh_rule(file_path):
    """Load and parse a Wazuh rule from XML."""
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    wazuh_rule = {
        'id': root.find('id').text,
        'level': root.find('level').text,
        'description': root.find('description').text,
        'commandline': root.find('commandline').text if root.find('commandline') else ''
    }
    
    return wazuh_rule
