from rule_engine.engine.parsers import load_rule, load_rules_from_directory, RuleLoader


def load_rule_cli(rule_path):
    try:
        loader = RuleLoader()
        rule = loader.load(rule_path)
        name = rule.get('name', rule.get('title', 'unknown'))
        fmt = loader.detect_format(rule_path)
        fmt_str = fmt.value if fmt else 'unknown'
        categories = rule.get('categories', [])
        cves = rule.get('cves', [])
        print(f"Loaded rule: {name}")
        print(f"  Format: {fmt_str}")
        print(f"  Categories: {', '.join(categories) if categories else 'none'}")
        if cves:
            print(f"  CVEs: {', '.join(cves)}")
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

def list_categories():
    from rule_engine.engine.categories import list_categories
    cats = list_categories()
    for slug, name in cats.items():
        print(f"  {slug}: {name}")
    return cats

list_categories_cli = list_categories
