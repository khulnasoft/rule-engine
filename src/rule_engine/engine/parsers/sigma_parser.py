import yaml


def parse_sigma_rule(file_path):
    with open(file_path, 'r') as file:
        rule = yaml.safe_load(file)

    if not validate_sigma_rule(rule):
        raise ValueError(f"Invalid Sigma rule: {file_path}")

    return rule


def validate_sigma_rule(rule):
    required_fields = ['title', 'description', 'logsource', 'detection', 'level']
    for field in required_fields:
        if field not in rule or rule[field] is None:
            print(f"Error: Missing required field '{field}' in Sigma rule.")
            return False
    return True


def load_sigma_rule(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)
