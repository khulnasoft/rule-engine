import requests

def send_to_wazuh(alert):
    url = "http://wazuh-manager:55000/alert"
    payload = {"alert": alert}
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, json=payload, headers=headers)
    return response.status_code
