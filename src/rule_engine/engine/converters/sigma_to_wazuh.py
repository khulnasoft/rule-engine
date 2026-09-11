import yaml


def convert_sigma_to_wazuh(sigma_rule):
    """Convert a Sigma rule to Wazuh XML format."""
    if not sigma_rule or not isinstance(sigma_rule, dict):
        raise ValueError("Invalid Sigma rule: must be a non-empty dictionary")
    ls = sigma_rule.get('logsource', {}) or {}
    det = sigma_rule.get('detection', {}) or {}
    sel = det.get('selection', {}) or {}
    cmdline = ' '.join(sel.get('CommandLine', []))
    wazuh_rule = f"""<group>
    <id>{sigma_rule.get('id', '0')}</id>
    <level>{sigma_rule.get('level', '0')}</level>
    <description>{sigma_rule.get('description', '')}</description>
    <group>{sigma_rule.get('behaviorgroup', '0')}</group>
    <classification>{sigma_rule.get('classification', '0')}</classification>
    <logsource>
        <category>{ls.get('category', 'unknown')}</category>
        <product>{ls.get('product', 'unknown')}</product>
    </logsource>
    <detection>
        <selection>
            <commandline>{cmdline}</commandline>
        </selection>
        <condition>{det.get('condition', 'all')}</condition>
    </detection>
</group>"""
    return wazuh_rule.strip()


def load_sigma_rule(file_path):
    """Load and parse a Sigma rule from YAML."""
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)
