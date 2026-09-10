import json

def match_rule(rule, event):
    # Example rule matching (could be regex, specific patterns, etc.)
    if rule['pattern'] in event:
        return True
    return False

def execute_rules_on_log(log, rules):
    matched_rules = []
    for rule in rules:
        if match_rule(rule, log):
            matched_rules.append(rule)
    return matched_rules
