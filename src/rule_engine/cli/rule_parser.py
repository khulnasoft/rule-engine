from rule_engine.engine.parsers import load_rule, load_rules_from_directory


def load_rule_cli(rule_path):
    try:
        rule = load_rule(rule_path)
        print(f"Loaded rule: {rule.get('name', rule.get('title', 'unknown'))}")
        print(f"Format: {rule}")
        return rule
    except ValueError as e:
        print(f"Error: {e}")
        return None
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return None


def load_rules(directory):
    return load_rules_from_directory(directory)

load_rules_cli = load_rules
