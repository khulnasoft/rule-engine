import requests
import json


def send_to_siem(alert_data, siem_type="splunk", splunk_hec_url=None, splunk_token=None,
                 elasticsearch_url=None, wazuh_api_url=None, wazuh_api_key=None):
    """Send alert data to a SIEM system."""
    if siem_type == "splunk":
        return send_to_splunk(alert_data, splunk_hec_url, splunk_token)
    elif siem_type == "elastic":
        return send_to_elastic(alert_data, elasticsearch_url)
    elif siem_type == "wazuh":
        return send_to_wazuh(alert_data, wazuh_api_url, wazuh_api_key)
    else:
        raise ValueError(f"Unsupported SIEM type: {siem_type}")


def send_to_splunk(alert_data, splunk_hec_url, splunk_token):
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
    return response.status_code


def send_to_elastic(alert_data, elasticsearch_url, index='alerts'):
    headers = {'Content-Type': 'application/json'}
    response = requests.post(f'{elasticsearch_url}/{index}/_doc', headers=headers, json=alert_data)
    if response.status_code == 201:
        print(f"Successfully sent alert to ElasticSearch: {alert_data}")
    else:
        print(f"Failed to send alert to ElasticSearch. Status code: {response.status_code}")
    return response.status_code


def send_to_wazuh(alert_data, wazuh_api_url, wazuh_api_key):
    headers = {
        'Authorization': f'Bearer {wazuh_api_key}',
        'Content-Type': 'application/json'
    }
    response = requests.post(f'{wazuh_api_url}/alerts', json=alert_data, headers=headers)
    if response.status_code == 200:
        print(f"Successfully sent alert to Wazuh: {alert_data}")
    else:
        print(f"Failed to send alert to Wazuh. Status code: {response.status_code}")
    return response.status_code
