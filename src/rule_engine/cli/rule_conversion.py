from rule_engine.engine.converters import convert_rule
from rule_engine.engine.models import RuleFormat


def convert_rule_cli(rule_path, target_format):
    try:
        from rule_engine.engine.parsers import load_rule
        rule = load_rule(rule_path)
        from_format = rule.get('format', RuleFormat.SIGMA.value) if isinstance(rule, dict) else RuleFormat.SIGMA.value
        result = convert_rule(rule, from_format, target_format)
        print(f"Converted rule to {target_format}: {result}")
        return result
    except ValueError as e:
        print(f"Error: {e}")
        return None
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return None
