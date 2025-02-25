# rule-engine/engine/integration/elastic_integration.py
import requests
import json

def send_to_elastic(alert_data, elasticsearch_url, index='alerts'):
    """Send the alert data to ElasticSearch."""
    headers = {'Content-Type': 'application/json'}
    
    response = requests.post(f'{elasticsearch_url}/{index}/_doc', headers=headers, json=alert_data)
    
    if response.status_code == 201:
        print(f"Successfully sent alert to ElasticSearch: {alert_data}")
    else:
        print(f"Failed to send alert to ElasticSearch. Status code: {response.status_code}")
        print(response.text)
