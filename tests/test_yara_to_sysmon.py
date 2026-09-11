import unittest
from rule_engine.engine.converters.yara_to_sysmon import convert_yara_to_sysmon, _determine_event_id
from rule_engine.engine.converters import convert_rule
from rule_engine.engine.parsers.yara_parser import parse_yara_rule_string


class TestYaraToSysmon(unittest.TestCase):

    def test_execution_to_event1(self):
        yara_rule = {
            "name": "MalwareExecution",
            "strings": ["cmd.exe", "powershell"],
            "condition": "all of them",
            "meta": {"category": "execution"},
        }
        result = convert_yara_to_sysmon(yara_rule)
        self.assertEqual(result["event_id"], "1")

    def test_network_to_event3(self):
        yara_rule = {
            "name": "NetworkConnection",
            "strings": ["evil.com", "192.168.1.1"],
            "condition": "any of them",
            "meta": {"category": "lateral-movement"},
        }
        result = convert_yara_to_sysmon(yara_rule)
        self.assertEqual(result["event_id"], "3")

    def test_file_creation_to_event11(self):
        yara_rule = {
            "name": "FileCreate",
            "strings": ["test.dll", "malware.exe"],
            "condition": "any of them",
            "meta": {"category": "malicious-documents"},
        }
        result = convert_yara_to_sysmon(yara_rule)
        self.assertEqual(result["event_id"], "11")

    def test_hex_strings_to_hexpattern_field(self):
        yara_rule = {
            "name": "HexSignature",
            "strings": ["4d5a9c00", "660f1f44"],
            "condition": "any of them",
            "meta": {},
        }
        result = convert_yara_to_sysmon(yara_rule)
        self.assertEqual(result.get("fields", {}).get("HexPattern"), "4d5a9c00660f1f44")

    def test_ascii_strings_to_commandline(self):
        yara_rule = {
            "name": "AsciiSignature",
            "strings": ["cmd.exe", "powershell"],
            "condition": "any of them",
            "meta": {},
        }
        result = convert_yara_to_sysmon(yara_rule)
        fields = result.get("fields", {})
        self.assertEqual(fields.get("CommandLine"), "cmd.exe")

    def test_default_event_id(self):
        yara_rule = {
            "name": "Unknown",
            "strings": ["test"],
            "condition": "all of them",
            "meta": {},
            "tags": [],
        }
        result = convert_yara_to_sysmon(yara_rule)
        self.assertEqual(result["event_id"], "1")

    def test_event_id_from_meta(self):
        yara_rule = {
            "name": "ExplicitEvent",
            "strings": ["test"],
            "condition": "all of them",
            "meta": {"event_id": "11"},
        }
        result = convert_yara_to_sysmon(yara_rule)
        self.assertEqual(result["event_id"], "11")

    def test_invalid_input_raises(self):
        with self.assertRaises(ValueError):
            convert_yara_to_sysmon(None)
        with self.assertRaises(ValueError):
            convert_yara_to_sysmon({})

    def test_string_input_raises(self):
        with self.assertRaises(ValueError):
            convert_yara_to_sysmon("rule X { strings: $a = test condition: $a }")

    def test_roundtrip_via_convert_rule(self):
        yara_rule = {
            "name": "RoundTrip",
            "format": "yara",
            "strings": ["cmd.exe"],
            "condition": "all of them",
            "meta": {"category": "execution"},
        }
        result = convert_rule(yara_rule, "yara", "sysmon")
        self.assertEqual(result["event_id"], "1")

    def test_select_xpath(self):
        yara_rule = {
            "name": "Test",
            "strings": ["test"],
            "condition": "all of them",
            "meta": {},
        }
        result = convert_yara_to_sysmon(yara_rule)
        self.assertIn("EventID=1", result.get("select", ""))

    def test_through_parse_and_convert(self):
        yara_content = '''rule ProcessCreate {
    meta:
        category = "execution"
    strings:
        $a = "cmd.exe"
    condition:
        $a
}'''
        parsed = parse_yara_rule_string(yara_content)
        result = convert_yara_to_sysmon(parsed)
        self.assertEqual(result["event_id"], "1")
        self.assertIn("cmd.exe", result.get("fields", {}).get("CommandLine", ""))


if __name__ == "__main__":
    unittest.main()
