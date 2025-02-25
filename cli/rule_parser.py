import yaml
import xml.etree.ElementTree as ET

def load_rules(rule_path):
    """Load and validate rules."""
    if rule_path.endswith('.yml') or rule_path.endswith('.yaml'):
        with open(rule_path, 'r') as file:
            rules = yaml.safe_load(file)
            print(f"Loaded YAML rule: {rules}")
            # You could add more validation here
    elif rule_path.endswith('.xml'):
        tree = ET.parse(rule_path)
        root = tree.getroot()
        print(f"Loaded XML rule: {ET.tostring(root)}")
    else:
        print("Unsupported rule format. Please provide a .yml, .yaml, or .xml file.")
