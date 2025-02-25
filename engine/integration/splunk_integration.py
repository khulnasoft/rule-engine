# rule-engine/engine/integration/splunk_integration.py
import requests
import json

def send_to_splunk(alert_data, splunk_hec_url, splunk_token):
    """Send alert data to Splunk via HTTP Event Collector (HEC)."""
    headers = {
        'Authorization': f'Splunk {splunk_token}',
        'Content-Type': 'application/json'
    }
    
    data = {
        'event': json.dumps(alert_data),
        'sourcetype': 'alert',
        'index': 'main'
    }
    
    response = requests.post(splunk_hec_url, headers=headers, json=data)
    
    if response.status_code == 200:
        print(f"Successfully sent alert to Splunk: {alert_data}")
    else:
        print(f"Failed to send alert to Splunk. Status code: {response.status_code}")
        print(response.text)
