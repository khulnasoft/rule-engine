from rule_engine.engine.categories import classify_rule

SIGMA_CATEGORY_TO_EVENTID = {
    "process_creation": "1",
    "file_creation": "11",
    "network_connection": "3",
    "process_terminated": "5",
    "file_delete": "23",
    "registry_add_delete": "12",
    "registry_set": "13",
    "registry_value_add": "14",
    "registry_value_delete": "15",
    "windows_service_create": "7",
    "windows_service_modify": "8",
    "driver_loaded": "6",
    "image_loaded": "7",
    "create_remote_thread": "8",
    "rawaccessread": "9",
    "process_access": "10",
    "file_create": "11",
    "wmi_activity": "19",
    "dns_query": "22",
}

SIGMA_FIELD_MAP = {
    "CommandLine": "CommandLine",
    "Image": "Image",
    "TargetImage": "TargetImage",
    "SourceImage": "SourceImage",
    "DestinationImage": "DestinationImage",
    "User": "User",
    "CommandLineLength": "CommandLineLength",
    "Description": "Description",
    "OriginalFileName": "OriginalFileName",
    "EventID": "EventID",
}


def convert_sigma_to_sysmon(sigma_rule):
    if not sigma_rule or not isinstance(sigma_rule, dict):
        raise ValueError("Invalid Sigma rule: must be a non-empty dictionary")

    ls = sigma_rule.get("logsource", {}) or {}
    category = ls.get("category", "")
    product = ls.get("product", "")
    service = ls.get("service", "")
    event_id = SIGMA_CATEGORY_TO_EVENTID.get(category, "1")

    det = sigma_rule.get("detection", {}) or {}
    selection = det.get("selection", {}) or {}
    condition = det.get("condition", "selection")

    match_on_fields = []
    for sigma_field, sysmon_field in SIGMA_FIELD_MAP.items():
        if sigma_field in selection:
            match_on_fields.append(f"<Binary Name=\"{sysmon_field}\">{selection[sigma_field]}</Binary>")

    match_on_xml = "".join(match_on_fields)
    select_xpath = f"*[System[(EventID={event_id})]]"

    description = sigma_rule.get("description", sigma_rule.get("title", "Sysmon rule"))
    name = description[:100] if len(description) > 100 else description

    rule_dict = {
        "name": name,
        "format": "sysmon",
        "description": description,
        "level": sigma_rule.get("level", 0),
        "event_id": event_id,
        "select": select_xpath,
        "fields": dict(selection),
        "metadata": {
            "name": name,
            "event_id": event_id,
            "sigma_category": category,
            "sigma_product": product,
            "sigma_service": service,
            "sigma_condition": condition,
        },
        "detection": {
            "select": select_xpath,
            "fields": dict(selection),
            "condition": condition,
        },
        "condition": select_xpath,
    }

    return classify_rule(rule_dict)
