import unittest
from rule_engine.engine.converters import convert_rule
from rule_engine.engine.converters.wazuh_to_sysmon import convert_wazuh_to_sysmon
from rule_engine.engine.models import RuleFormat


class TestWazuhToSysmon(unittest.TestCase):

    def test_process_creation(self):
        wazuh_rule = {
            "id": "200",
            "level": 3,
            "description": "Sysmon - Event 1: Process creation",
            "match": "cmd.exe",
            "group": "sysmon_event1,",
        }
        result = convert_wazuh_to_sysmon(wazuh_rule)
        self.assertEqual(result["event_id"], "1")
        self.assertIn("CommandLine", result.get("fields", {}))

    def test_network_connection(self):
        wazuh_rule = {
            "id": "201",
            "level": 0,
            "description": "Sysmon - Event 3: Network connection",
            "group": "sysmon_event3,",
        }
        result = convert_wazuh_to_sysmon(wazuh_rule)
        self.assertEqual(result["event_id"], "3")

    def test_file_creation(self):
        wazuh_rule = {
            "id": "202",
            "level": 0,
            "description": "Sysmon - Event 11: File create",
            "group": "sysmon_event11,",
        }
        result = convert_wazuh_to_sysmon(wazuh_rule)
        self.assertEqual(result["event_id"], "11")

    def test_fields_from_match(self):
        wazuh_rule = {
            "id": "200",
            "level": 3,
            "description": "Sysmon - Event 1: Process creation",
            "match": "cmd.exe",
            "group": "sysmon_event1,",
        }
        result = convert_wazuh_to_sysmon(wazuh_rule)
        self.assertEqual(result["fields"].get("CommandLine"), "cmd.exe")

    def test_fields_mapping(self):
        wazuh_rule = {
            "id": "200",
            "level": 3,
            "description": "Sysmon - Event 1",
            "fields": {"commandline": "cmd.exe", "image": "C:\\test.exe"},
            "group": "sysmon_event1,",
        }
        result = convert_wazuh_to_sysmon(wazuh_rule)
        fields = result.get("fields", {})
        self.assertEqual(fields.get("CommandLine"), "cmd.exe")
        self.assertEqual(fields.get("Image"), "C:\\test.exe")

    def test_default_event_id(self):
        wazuh_rule = {
            "id": "999",
            "level": 0,
            "description": "Generic Wazuh rule",
            "group": "generic,",
        }
        result = convert_wazuh_to_sysmon(wazuh_rule)
        self.assertEqual(result["event_id"], "1")

    def test_invalid_rule_raises(self):
        with self.assertRaises(ValueError):
            convert_wazuh_to_sysmon(None)
        with self.assertRaises(ValueError):
            convert_wazuh_to_sysmon({})

    def test_roundtrip_via_convert_rule(self):
        wazuh_rule = {
            "id": "200",
            "level": 3,
            "description": "Sysmon - Event 1: Process creation",
            "match": "cmd.exe",
            "group": "sysmon_event1,",
        }
        result = convert_rule(wazuh_rule, "wazuh", "sysmon")
        self.assertEqual(result["event_id"], "1")

    def test_select_xpath(self):
        wazuh_rule = {
            "id": "200",
            "level": 3,
            "description": "Sysmon - Event 1: Process creation",
            "group": "sysmon_event1,",
        }
        result = convert_wazuh_to_sysmon(wazuh_rule)
        self.assertIn("EventID=1", result.get("select", ""))

    def test_description_includes_event_id(self):
        wazuh_rule = {
            "id": "200",
            "level": 3,
            "description": "Sysmon - Event 1: Process creation",
            "group": "sysmon_event1,",
        }
        result = convert_wazuh_to_sysmon(wazuh_rule)
        self.assertIn("Sysmon Event 1", result.get("name", ""))


if __name__ == "__main__":
    unittest.main()
