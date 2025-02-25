# rule-engine/engine/parsers/sigma_parser.py
import yaml

def parse_sigma_rule(file_path):
    """Parse a Sigma rule from a YAML file."""
    with open(file_path, 'r') as file:
        rule = yaml.safe_load(file)
    
    # Validate the rule structure
    if not validate_sigma_rule(rule):
        raise ValueError(f"Invalid Sigma rule: {file_path}")
    
    return rule

def validate_sigma_rule(rule):
    """Validate the structure of a Sigma rule."""
    required_fields = ['title', 'description', 'logsource', 'detection', 'level']
    
    for field in required_fields:
        if field not in rule:
            print(f"Error: Missing required field '{field}' in Sigma rule.")
            return False
    return True
