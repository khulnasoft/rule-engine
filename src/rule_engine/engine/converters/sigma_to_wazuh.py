# rule-engine/engine/converters/sigma_to_wazuh.py

import yaml

def convert_sigma_to_wazuh(sigma_rule):
    """Convert a Sigma rule to Wazuh XML format."""
    wazuh_rule = f"""
<group>
    <id>{sigma_rule['id']}</id>
    <level>{sigma_rule['level']}</level>
    <description>{sigma_rule['description']}</description>
    <group>{sigma_rule['behaviorgroup']}</group>
    <classification>{sigma_rule['classification']}</classification>
    <logsource>
        <category>{sigma_rule['logsource']['category']}</category>
        <product>{sigma_rule['logsource']['product']}</product>
    </logsource>
    <detection>
        <selection>
            <commandline>{' '.join(sigma_rule.get('detection', {}).get('selection', {}).get('CommandLine', []))}</commandline>
        </selection>
        <condition>{sigma_rule['detection']['condition']}</condition>
    </detection>
</group>
    """
    return wazuh_rule.strip()

def load_sigma_rule(file_path):
    """Load and parse a Sigma rule from YAML."""
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)
