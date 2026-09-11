from rule_engine.engine.executors import execute_rules, get_executor
from rule_engine.engine.parsers import load_rule, load_rules_from_directory
from rule_engine.engine.models import RuleFormat


def execute_rules_cli(log_file, rule_path=None):
    try:
        if rule_path:
            rules = [load_rule(rule_path)]
        else:
            rules = load_rules_from_directory("rules")
        if not rules:
            print("No rules loaded")
            return []
        results = execute_rules(rules, log_file)
        print(f"Executed {len(rules)} rules on {log_file}: {len(results)} matches found")
        for r in results:
            print(f"  - {r}")
        return results
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return []

execute_rules_cli = execute_rules_cli
