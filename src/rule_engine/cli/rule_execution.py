from rule_engine.engine.executors import execute_rules


def execute_rules_cli(log_file):
    try:
        results = execute_rules([], log_file)
        print(f"Executed rules on {log_file}: {len(results)} matches found")
        for r in results:
            print(f"  - {r}")
        return results
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return []
