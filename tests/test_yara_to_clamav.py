import unittest
from rule_engine.engine.converters import convert_rule
from rule_engine.engine.models import RuleFormat
from rule_engine.engine.parsers.yara_parser import parse_yara_rule_string
from rule_engine.engine.converters.yara_to_clamav import convert_yara_to_clamav


class TestYaraToClamav(unittest.TestCase):

    def test_hex_strings_to_clamav(self):
        yara_content = '''rule TestHex {
    strings:
        $a1 = {4d 5a 9c 00 00}
        $a2 = {66 0F 1F 44 00 00}
    condition:
        all of them
}'''
        parsed = parse_yara_rule_string(yara_content)
        result = convert_yara_to_clamav(parsed)
        self.assertIn("clamav", result.get("format", ""))
        self.assertIn("3;", result.get("condition", ""))
        self.assertIn("4d5a9c0000", result.get("condition", ""))
        self.assertIn("660F1F440000", result.get("condition", ""))

    def test_ascii_strings_to_clamav(self):
        yara_content = '''rule TestAscii {
    strings:
        $a1 = "cmd.exe"
        $a2 = "powershell"
    condition:
        all of them
}'''
        parsed = parse_yara_rule_string(yara_content)
        result = convert_yara_to_clamav(parsed)
        self.assertIn("0;", result.get("condition", ""))
        self.assertIn("cmd.exe", result.get("condition", ""))
        self.assertIn("powershell", result.get("condition", ""))

    def test_rule_name_in_output(self):
        yara_content = '''rule MyMalware {
    strings:
        $a1 = {41 42 43}
    condition:
        $a1
}'''
        parsed = parse_yara_rule_string(yara_content)
        result = convert_yara_to_clamav(parsed)
        self.assertIn("MyMalware", result.get("name", ""))

    def test_invalid_input_raises(self):
        with self.assertRaises(ValueError):
            convert_yara_to_clamav(None)
        with self.assertRaises(ValueError):
            convert_yara_to_clamav("")

    def test_string_input_raises(self):
        with self.assertRaises(ValueError):
            convert_yara_to_clamav('rule X { strings: $a = "test" condition: $a }')

    def test_no_strings_raises(self):
        yara_rule = {"name": "Empty", "condition": "true"}
        with self.assertRaises(ValueError):
            convert_yara_to_clamav(yara_rule)

    def test_no_wide_when_absent_from_condition(self):
        yara_rule = {"name": "TestWide", "strings": ["test"], "condition": "$a1"}
        result = convert_yara_to_clamav(yara_rule)
        self.assertFalse(result["metadata"].get("wide", True))
        self.assertNotIn("_wide", result.get("condition", ""))

    def test_roundtrip_via_convert_rule(self):
        yara_rule = {
            "name": "RoundTrip",
            "format": "yara",
            "strings": ["41 42 43", "test"],
            "condition": "all of them",
        }
        result = convert_rule(yara_rule, "yara", "clamav")
        self.assertIn("clamav", result.get("format", ""))
        self.assertIn("3;", result.get("condition", ""))
        self.assertIn("414243", result.get("condition", ""))

    def test_cve_classification(self):
        yara_content = '''rule TestCVE {
    strings:
        $a1 = "CVE-2021-12345"
    condition:
        $a1
}'''
        parsed = parse_yara_rule_string(yara_content)
        result = convert_yara_to_clamav(parsed)
        self.assertIn("cve-rules", result.get("categories", []))


if __name__ == "__main__":
    unittest.main()
