from rule_engine.engine.integration import send_to_siem


def send_to_siem_cli(rule_path, siem_type="splunk"):
    try:
        alert_data = {"rule": rule_path, "siem_type": siem_type}
        send_to_siem(alert_data, siem_type=siem_type)
        print(f"Sent rule to {siem_type}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False
