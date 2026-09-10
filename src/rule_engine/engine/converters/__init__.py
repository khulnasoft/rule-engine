from rule_engine.engine.models import Rule, RuleFormat
from rule_engine.engine.parsers.yara_parser import parse_yara_rule, parse_yara_rule_string
from rule_engine.engine.parsers.sigma_parser import parse_sigma_rule
from rule_engine.engine.parsers.wazuh_parser import parse_wazuh_rule
from rule_engine.engine.converters.yara_to_sigma import convert_yara_to_sigma
from rule_engine.engine.converters.yara_to_wazuh import convert_yara_to_wazuh
from rule_engine.engine.converters.sigma_to_yara import convert_sigma_to_yara
from rule_engine.engine.converters.sigma_to_wazuh import convert_sigma_to_wazuh
from rule_engine.engine.converters.wazuh_to_sigma import convert_wazuh_to_sigma
from rule_engine.engine.converters.wazuh_to_yara import convert_wazuh_to_yara


def convert_rule(rule_content, from_format, to_format):
    from_format = RuleFormat(from_format)
    to_format = RuleFormat(to_format)

    if from_format == to_format:
        return rule_content

    if from_format == RuleFormat.SIGMA and to_format == RuleFormat.YARA:
        return convert_sigma_to_yara(rule_content)
    elif from_format == RuleFormat.SIGMA and to_format == RuleFormat.WAZUH:
        return convert_sigma_to_wazuh(rule_content)
    elif from_format == RuleFormat.YARA and to_format == RuleFormat.SIGMA:
        if isinstance(rule_content, str):
            rule_content = parse_yara_rule_string(rule_content)
        return convert_yara_to_sigma(rule_content)
    elif from_format == RuleFormat.YARA and to_format == RuleFormat.WAZUH:
        if isinstance(rule_content, str):
            rule_content = parse_yara_rule_string(rule_content)
        return convert_yara_to_wazuh(rule_content)
    elif from_format == RuleFormat.WAZUH and to_format == RuleFormat.SIGMA:
        return convert_wazuh_to_sigma(rule_content)
    elif from_format == RuleFormat.WAZUH and to_format == RuleFormat.YARA:
        return convert_wazuh_to_yara(rule_content)
    else:
        raise ValueError(f"Unsupported conversion: {from_format.value} -> {to_format.value}")
