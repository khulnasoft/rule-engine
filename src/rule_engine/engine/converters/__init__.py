import yaml
import xml.etree.ElementTree as ET
from rule_engine.engine.models import Rule, RuleFormat
from rule_engine.engine.parsers.yara_parser import parse_yara_rule, parse_yara_rule_string
from rule_engine.engine.parsers.sigma_parser import parse_sigma_rule
from rule_engine.engine.parsers.wazuh_parser import parse_wazuh_rule
from rule_engine.engine.parsers.sysmon_parser import parse_sysmon_rule
from rule_engine.engine.converters.yara_to_clamav import convert_yara_to_clamav
from rule_engine.engine.converters.yara_to_sigma import convert_yara_to_sigma
from rule_engine.engine.converters.yara_to_sysmon import convert_yara_to_sysmon
from rule_engine.engine.converters.yara_to_wazuh import convert_yara_to_wazuh
from rule_engine.engine.converters.sigma_to_yara import convert_sigma_to_yara
from rule_engine.engine.converters.sigma_to_wazuh import convert_sigma_to_wazuh
from rule_engine.engine.converters.sigma_to_sysmon import convert_sigma_to_sysmon
from rule_engine.engine.converters.wazuh_to_sigma import convert_wazuh_to_sigma
from rule_engine.engine.converters.wazuh_to_yara import convert_wazuh_to_yara
from rule_engine.engine.converters.sysmon_to_wazuh import convert_sysmon_to_wazuh
from rule_engine.engine.converters.wazuh_to_sysmon import convert_wazuh_to_sysmon


def convert_rule(rule_content, from_format, to_format):
    from_format = RuleFormat(from_format)
    to_format = RuleFormat(to_format)

    if from_format == to_format:
        return rule_content

    if from_format == RuleFormat.SIGMA and to_format == RuleFormat.YARA:
        return convert_sigma_to_yara(rule_content)
    elif from_format == RuleFormat.SIGMA and to_format == RuleFormat.WAZUH:
        return convert_sigma_to_wazuh(rule_content)
    elif from_format == RuleFormat.SIGMA and to_format == RuleFormat.SYSMON:
        return convert_sigma_to_sysmon(rule_content)
    elif from_format == RuleFormat.YARA and to_format == RuleFormat.SIGMA:
        if isinstance(rule_content, str):
            rule_content = parse_yara_rule_string(rule_content)
        return convert_yara_to_sigma(rule_content)
    elif from_format == RuleFormat.YARA and to_format == RuleFormat.WAZUH:
        if isinstance(rule_content, str):
            rule_content = parse_yara_rule_string(rule_content)
        return convert_yara_to_wazuh(rule_content)
    elif from_format == RuleFormat.YARA and to_format == RuleFormat.CLAMAV:
        if isinstance(rule_content, str):
            rule_content = parse_yara_rule_string(rule_content)
        return convert_yara_to_clamav(rule_content)
    elif from_format == RuleFormat.YARA and to_format == RuleFormat.SYSMON:
        if isinstance(rule_content, str):
            rule_content = parse_yara_rule_string(rule_content)
        return convert_yara_to_sysmon(rule_content)
    elif from_format == RuleFormat.WAZUH and to_format == RuleFormat.SIGMA:
        return convert_wazuh_to_sigma(rule_content)
    elif from_format == RuleFormat.WAZUH and to_format == RuleFormat.YARA:
        return convert_wazuh_to_yara(rule_content)
    elif from_format == RuleFormat.WAZUH and to_format == RuleFormat.SYSMON:
        return convert_wazuh_to_sysmon(rule_content)
    elif from_format == RuleFormat.SYSMON and to_format == RuleFormat.SIGMA:
        if isinstance(rule_content, str):
            rule_content = parse_sysmon_rule(rule_content)
        return _sysmon_to_sigma(rule_content)
    elif from_format == RuleFormat.SYSMON and to_format == RuleFormat.WAZUH:
        if isinstance(rule_content, str):
            rule_content = parse_sysmon_rule(rule_content)
        return convert_sysmon_to_wazuh(rule_content)
    else:
        raise ValueError(f"Unsupported conversion: {from_format.value} -> {to_format.value}")


def _sysmon_to_sigma(sysmon_rule):
    event_id = sysmon_rule.get("event_id", "1")
    fields = sysmon_rule.get("fields", {})
    select = sysmon_rule.get("select", "")
    description = sysmon_rule.get("description", "Sysmon rule")
    level = sysmon_rule.get("level", 0)

    sigma_fields = {}
    field_map = {
        "CommandLine": "CommandLine",
        "Image": "Image",
        "TargetImage": "TargetImage",
        "SourceImage": "SourceImage",
        "DestinationImage": "DestinationImage",
        "User": "User",
        "Description": "Description",
        "OriginalFileName": "OriginalFileName",
        "EventID": "EventID",
    }
    for sysmon_name, sigma_name in field_map.items():
        if sysmon_name in fields:
            sigma_fields[sigma_name] = fields[sysmon_name]

    category = "process_creation"
    for ev_id, cat in {
        "1": "process_creation",
        "3": "network_connection",
        "11": "file_creation",
        "5": "process_terminated",
        "23": "file_delete",
    }.items():
        if event_id == ev_id:
            category = cat
            break

    sigma_rule = {
        "title": description,
        "description": description,
        "logsource": {
            "category": category,
            "product": "windows",
            "service": "sysmon" if event_id != "1" else "Microsoft-Windows-Sysmon/Operational",
        },
        "detection": {
            "selection": sigma_fields,
            "condition": "selection",
        },
        "level": level,
        "id": "sysmon-converted",
    }
    return yaml.dump(sigma_rule, default_flow_style=False)
