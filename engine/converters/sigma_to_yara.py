# rule-engine/engine/converters/sigma_to_yara.py

import yaml

def convert_sigma_to_yara(sigma_rule):
    """Convert a Sigma rule to YARA format."""
    yara_rule = []

    # YARA rule name
    yara_rule.append(f"rule {sigma_rule['title']} {{")
    
    # YARA strings section
    yara_rule.append("    strings:")
    for string in sigma_rule.get('detection', {}).get('selection', {}).get('CommandLine', []):
        yara_rule.append(f"        $a = \"{string}\"")
    
    # YARA condition section
    yara_rule.append("    condition:")
    yara_rule.append(f"        {sigma_rule['detection']['condition']}")

    yara_rule.append("}")

    return "\n".join(yara_rule)

def load_sigma_rule(file_path):
    """Load and parse a Sigma rule from YAML."""
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)
