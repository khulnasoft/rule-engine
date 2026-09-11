import unittest
import yaml
from rule_engine.engine.converters.sigma_to_sysmon import convert_sigma_to_sysmon
from rule_engine.engine.converters import convert_rule
from rule_engine.engine.models import RuleFormat


class TestSigmaToSysmon(unittest.TestCase):

    def test_process_creation_conversion(self):
        sigma_rule = {
            "title": "Detect Process Creation",
            "description": "Detects suspicious process creation events",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {"CommandLine": "cmd.exe", "User": "admin"},
                "condition": "selection",
            },
            "level": "high",
        }
        result = convert_sigma_to_sysmon(sigma_rule)
        self.assertEqual(result["event_id"], "1")
        self.assertIn("CommandLine", result["fields"])
        self.assertIn("process_creation", result["metadata"].get("sigma_category", ""))
        self.assertIn("primary_category", result)

    def test_network_connection_conversion(self):
        sigma_rule = {
            "title": "Detect Network Connections",
            "logsource": {"category": "network_connection", "product": "windows"},
            "detection": {
                "selection": {"DestinationHostname": "evil.com"},
                "condition": "selection",
            },
        }
        result = convert_sigma_to_sysmon(sigma_rule)
        self.assertEqual(result["event_id"], "3")

    def test_file_creation_conversion(self):
        sigma_rule = {
            "title": "Detect File Creation",
            "logsource": {"category": "file_creation", "product": "windows"},
            "detection": {
                "selection": {"TargetFilename": "C:\\temp\\test.dll"},
                "condition": "selection",
            },
        }
        result = convert_sigma_to_sysmon(sigma_rule)
        self.assertEqual(result["event_id"], "11")

    def test_unknown_category_defaults_to_event1(self):
        sigma_rule = {
            "title": "Unknown Category Rule",
            "logsource": {"category": "unknown", "product": "windows"},
            "detection": {"selection": {"test": "value"}, "condition": "selection"},
        }
        result = convert_sigma_to_sysmon(sigma_rule)
        self.assertEqual(result["event_id"], "1")

    def test_invalid_rule_raises(self):
        with self.assertRaises(ValueError):
            convert_sigma_to_sysmon(None)

    def test_missing_detection_fields(self):
        sigma_rule = {"title": "Minimal", "logsource": {"category": "process_creation"}}
        result = convert_sigma_to_sysmon(sigma_rule)
        self.assertEqual(result["event_id"], "1")
        self.assertEqual(result["fields"], {})


class TestConvertRuleSysmon(unittest.TestCase):

    def test_convert_rule_sigma_to_sysmon(self):
        sigma_rule = {
            "title": "Process Creation Test",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {"Image": "cmd.exe"},
                "condition": "selection",
            },
        }
        result = convert_rule(sigma_rule, "sigma", "sysmon")
        self.assertEqual(result["event_id"], "1")
        self.assertIn("Image", result.get("fields", {}))

    def test_convert_rule_sysmon_to_sigma(self):
        sysmon_rule = {
            "name": "Sysmon Event 1",
            "format": "sysmon",
            "event_id": "1",
            "fields": {"Image": "cmd.exe"},
            "select": "*[System[(EventID=1)]]",
            "condition": "*[System[(EventID=1)]]",
            "description": "Sysmon Event 1",
            "level": 0,
        }
        result = convert_rule(sysmon_rule, "sysmon", "sigma")
        parsed = yaml.safe_load(result)
        self.assertIn("detection", parsed)
        self.assertEqual(parsed["logsource"]["category"], "process_creation")

    def test_convert_rule_same_format_returns_rule(self):
        rule = {"name": "test", "format": "sysmon"}
        result = convert_rule(rule, "sysmon", "sysmon")
        self.assertEqual(result, rule)

    def test_convert_rule_unsupported(self):
        with self.assertRaises(ValueError):
            convert_rule({"name": "test"}, "clamav", "yara")


if __name__ == "__main__":
    unittest.main()
