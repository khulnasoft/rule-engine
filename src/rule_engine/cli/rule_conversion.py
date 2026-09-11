from rule_engine.engine.converters import convert_rule
from rule_engine.engine.models import RuleFormat
from rule_engine.engine.parsers import load_rule, RuleLoader


def convert_rule_cli(rule_path, target_format):
    try:
        loader = RuleLoader()
        rule = loader.load(rule_path)
        from_format = loader.detect_format(rule_path)
        if from_format is None:
            from_format = rule.get('format') if isinstance(rule, dict) else RuleFormat.SIGMA
        result = convert_rule(rule, from_format.value, target_format)
        print(f"Converted from {from_format.value} to {target_format}")
        return result
    except ValueError as e:
        print(f"Error: {e}")
        return None
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return None
