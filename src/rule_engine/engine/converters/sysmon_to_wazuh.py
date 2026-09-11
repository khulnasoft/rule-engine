from rule_engine.engine.categories import classify_rule

SYSMON_EVENTID_TO_WAZUH_ID = {
    "1": 61603, "2": 61604, "3": 61605, "4": 61606, "5": 61607,
    "6": 61608, "7": 61609, "8": 61610, "9": 61611, "10": 61612,
    "11": 61613, "12": 61614, "13": 61615, "14": 61616, "15": 61617,
    "16": 61618, "17": 61619, "18": 61620, "19": 61621, "20": 61622,
    "21": 61623, "22": 61624, "23": 61625, "24": 61626, "25": 61627,
    "26": 61628, "27": 61629, "28": 61630, "29": 61631, "30": 61632,
}

SYSMON_FIELD_TO_WAZUH_NAME = {
    "CommandLine": "win.system.commandLine",
    "Image": "win.system.image",
    "TargetImage": "win.system.targetImage",
    "SourceImage": "win.system.sourceImage",
    "DestinationImage": "win.system.destinationImage",
    "User": "win.system.user",
    "Description": "win.system.description",
    "OriginalFileName": "win.system.originalFileName",
    "EventID": "win.system.eventID",
    "ProcessGuid": "win.system.processGuid",
    "ProcessId": "win.system.processId",
    "FileVersion": "win.system.fileVersion",
    "UserGuid": "win.system.userGuid",
    "LogonGuid": "win.system.logonGuid",
    "TerminalSessionId": "win.system.terminalSessionId",
    "IntegrityLevel": "win.system.integrityLevel",
    "ParentCommandLine": "win.system.parentCommandLine",
    "ParentImage": "win.system.parentImage",
    "ParentProcessGuid": "win.system.parentProcessGuid",
    "ParentProcessId": "win.system.parentProcessId",
    "Hash": "win.system.hash",
    "Signed": "win.system.signed",
    "Signature": "win.system.signature",
    "SignatureStatus": "win.system.signatureStatus",
    "SourceHostname": "win.system.sourceHostname",
    "SourcePort": "win.system.sourcePort",
    "DestinationHostname": "win.system.destinationHostname",
    "DestinationPort": "win.system.destinationPort",
    "Protocol": "win.system.protocol",
    "Initiated": "win.system.initiated",
    "PacketDir": "win.system.packetDir",
    "IpVersion": "win.system.ipVersion",
    "ScopeId": "win.system.scopeId",
}

SYSMON_CATEGORY_MAP = {
    "1": "process_creation", "2": "file_creation", "3": "network_connection",
    "5": "process_terminated", "11": "file_creation", "23": "file_deletion",
}


def convert_sysmon_to_wazuh(sysmon_rule):
    if not sysmon_rule or not isinstance(sysmon_rule, dict):
        raise ValueError("Invalid Sysmon rule: must be a non-empty dictionary")

    event_id = sysmon_rule.get("event_id", "1")
    fields = sysmon_rule.get("fields", {})
    description = sysmon_rule.get("description", f"Sysmon Event {event_id}")
    level = sysmon_rule.get("level", 0)

    rule_id = SYSMON_EVENTID_TO_WAZUH_ID.get(event_id, 60000 + int(event_id) * 10)
    category = SYSMON_CATEGORY_MAP.get(event_id, "sysmon")

    wazuh_fields = []
    for sysmon_field, value in fields.items():
        wazuh_name = SYSMON_FIELD_TO_WAZUH_NAME.get(sysmon_field, sysmon_field)
        wazuh_fields.append(f"<field name=\"{wazuh_name}\">{value}</field>")

    group_tag = f"sysmon_event{event_id}"

    xml = f"""<group name="windows,sysmon,">
    <rule id="{rule_id}" level="{level}">
        <description>{description}</description>
        <group>{group_tag}</group>"""

    if fields:
        xml += "\n        <fields>"
        for field_xml in wazuh_fields:
            xml += field_xml
        xml += "</fields>"

    xml += "\n    </rule>\n</group>"

    rule_dict = {
        "id": str(rule_id),
        "level": level,
        "description": description,
        "group": group_tag,
        "fields": dict(fields),
        "format": "wazuh",
        "name": description,
        "metadata": {
            "source_format": "sysmon",
            "event_id": event_id,
            "category": category,
        },
    }

    return classify_rule(rule_dict)
