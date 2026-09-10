# rule-engine/engine/converters/wazuh_to_sigma.py

import xml.etree.ElementTree as ET

def convert_wazuh_to_sigma(wazuh_rule):
    """
    Convert a Wazuh XML rule to Sigma format.

    Parameters:
    - wazuh_rule (dict): The Wazuh rule to be converted.

    Returns:
    - dict: The converted Sigma rule.
    """
    # Create a Sigma rule dictionary with the necessary fields
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
    """
    Load and parse a Wazuh rule from XML.

    Parameters:
    - file_path (str): The path to the Wazuh rule file.

    Returns:
    - dict: The parsed Wazuh rule.
    """
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    # Extract relevant fields from the XML and create a Wazuh rule dictionary
    wazuh_rule = {
        'id': root.find('id').text,
        'level': root.find('level').text,
        'description': root.find('description').text,
        'commandline': root.find('commandline').text if root.find('commandline') else ''
    }
    
    return wazuh_rule
