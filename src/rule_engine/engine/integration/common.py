# rule-engine/engine/integration/common.py

import json

def log_alert_data(alert_data):
    """Helper function to log alert data (could be extended for file logging)."""
    print(json.dumps(alert_data, indent=4))

def create_alert_message(rule_name, match_data):
    """Helper function to create a structured alert message."""
    return {
        "rule_name": rule_name,
        "match_data": match_data,
        "timestamp": "2025-02-25T00:00:00Z",
        "severity": "high",
        "status": "detected"
    }
