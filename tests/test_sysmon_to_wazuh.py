import unittest
from rule_engine.engine.converters.sysmon_to_wazuh import convert_sysmon_to_wazuh
from rule_engine.engine.converters import convert_rule
from rule_engine.engine.models import RuleFormat


class TestSysmonToWazuh(unittest.TestCase):

    def test_process_creation(self):
        sysmon_rule = {
            "name": "Sysmon Event 1",
            "format": "sysmon",
            "event_id": "1",
            "fields": {"Image": "cmd.exe", "User": "admin"},
            "description": "Sysmon - Event 1: Process creation",
            "level": 3,
        }
        result = convert_sysmon_to_wazuh(sysmon_rule)
        self.assertEqual(result["id"], "61603")
        self.assertEqual(result["level"], 3)
        self.assertIn("process_creation", result.get("metadata", {}).get("category", ""))

    def test_network_connection(self):
        sysmon_rule = {
            "name": "Sysmon Event 3",
            "format": "sysmon",
            "event_id": "3",
            "fields": {"DestinationHostname": "evil.com"},
            "description": "Sysmon - Event 3: Network connection",
            "level": 0,
        }
        result = convert_sysmon_to_wazuh(sysmon_rule)
        self.assertEqual(result["id"], "61605")

    def test_file_creation(self):
        sysmon_rule = {
            "name": "Sysmon Event 11",
            "format": "sysmon",
            "event_id": "11",
            "fields": {"TargetFilename": "C:\\test.dll"},
            "description": "Sysmon - Event 11: File create",
            "level": 0,
        }
        result = convert_sysmon_to_wazuh(sysmon_rule)
        self.assertEqual(result["id"], "61613")

    def test_default_rule_id(self):
        sysmon_rule = {
            "name": "Unknown Event",
            "format": "sysmon",
            "event_id": "99",
            "fields": {},
            "description": "Unknown event",
            "level": 0,
        }
        result = convert_sysmon_to_wazuh(sysmon_rule)
        self.assertEqual(result["id"], "60990")

    def test_invalid_rule_raises(self):
        with self.assertRaises(ValueError):
            convert_sysmon_to_wazuh(None)
        with self.assertRaises(ValueError):
            convert_sysmon_to_wazuh({})

    def test_empty_fields(self):
        sysmon_rule = {
            "name": "No Fields",
            "format": "sysmon",
            "event_id": "1",
            "fields": {},
            "description": "No fields",
            "level": 0,
        }
        result = convert_sysmon_to_wazuh(sysmon_rule)
        self.assertEqual(result["id"], "61603")
        self.assertEqual(result.get("fields"), {})

    def test_roundtrip_via_convert_rule(self):
        sysmon_rule = {
            "name": "Test",
            "format": "sysmon",
            "event_id": "1",
            "fields": {"Image": "cmd.exe"},
            "description": "Test event",
            "level": 0,
        }
        result = convert_rule(sysmon_rule, "sysmon", "wazuh")
        self.assertEqual(result["id"], "61603")
        self.assertIn("Test event", result.get("description", ""))

    def test_field_mapping(self):
        sysmon_rule = {
            "name": "Test",
            "format": "sysmon",
            "event_id": "1",
            "fields": {"CommandLine": "cmd.exe", "Image": "cmd.exe"},
            "description": "Test",
            "level": 0,
        }
        result = convert_sysmon_to_wazuh(sysmon_rule)
        self.assertEqual(result.get("fields", {}).get("CommandLine"), "cmd.exe")
        self.assertEqual(result.get("fields", {}).get("Image"), "cmd.exe")
        from rule_engine.engine.converters.sysmon_to_wazuh import SYSMON_FIELD_TO_WAZUH_NAME
        self.assertIn("CommandLine", SYSMON_FIELD_TO_WAZUH_NAME)
        self.assertIn("Image", SYSMON_FIELD_TO_WAZUH_NAME)


if __name__ == "__main__":
    unittest.main()
