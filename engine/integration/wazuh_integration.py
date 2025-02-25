# rule-engine/engine/integration/wazuh_integration.py
import requests

def send_to_wazuh(alert_data, wazuh_api_url, wazuh_api_key):
    """Send the alert data to Wazuh via API."""
    headers = {
        'Authorization': f'Bearer {wazuh_api_key}',
        'Content-Type': 'application/json'
    }
    
    response = requests.post(f'{wazuh_api_url}/alerts', json=alert_data, headers=headers)
    
    if response.status_code == 200:
        print(f"Successfully sent alert to Wazuh: {alert_data}")
    else:
        print(f"Failed to send alert to Wazuh. Status code: {response.status_code}")
        print(response.text)
