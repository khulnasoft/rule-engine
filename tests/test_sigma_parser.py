import unittest
import tempfile
import os
from rule_engine.engine.parsers.sigma_parser import (
    parse_sigma_rule, validate_sigma_rule,
    has_timeline_fields, detect_timeline, load_sigma_rule,
)


class TestSigmaParserEnhanced(unittest.TestCase):

    def test_valid_sigma_rule(self):
        rule = {
            "title": "Test Rule",
            "description": "A valid test rule",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {"selection": {"CommandLine": "cmd.exe"}, "condition": "selection"},
            "level": "high",
        }
        self.assertTrue(validate_sigma_rule(rule))

    def test_missing_required_field(self):
        rule = {"title": "Test"}
        self.assertFalse(validate_sigma_rule(rule))

    def test_none_required_field(self):
        rule = {
            "title": "Test", "description": None,
            "logsource": {}, "detection": {}, "level": None,
        }
        self.assertFalse(validate_sigma_rule(rule))

    def test_invalid_logsource_product(self):
        rule = {
            "title": "Test", "description": "Test",
            "logsource": {"product": "unknown_platform", "category": "process_creation"},
            "detection": {"selection": {"CommandLine": "cmd.exe"}, "condition": "selection"},
            "level": "medium",
        }
        result = validate_sigma_rule(rule)
        self.assertTrue(result)

    def test_invalid_logsource_category(self):
        rule = {
            "title": "Test", "description": "Test",
            "logsource": {"product": "windows", "category": "unknown_cat"},
            "detection": {"selection": {"CommandLine": "cmd.exe"}, "condition": "selection"},
            "level": "medium",
        }
        result = validate_sigma_rule(rule)
        self.assertTrue(result)

    def test_detection_without_selection_or_condition(self):
        rule = {
            "title": "Test", "description": "Test",
            "logsource": {"product": "windows"}, "detection": {},
            "level": "medium",
        }
        self.assertFalse(validate_sigma_rule(rule))

    def test_detection_with_list_values(self):
        rule = {
            "title": "Test", "description": "Test",
            "logsource": {"product": "windows"},
            "detection": {"selection": {"CommandLine": ["cmd.exe", "powershell"]}, "condition": "selection"},
            "level": "medium",
        }
        self.assertTrue(validate_sigma_rule(rule))

    def test_invalid_level(self):
        rule = {
            "title": "Test", "description": "Test",
            "logsource": {"product": "windows"},
            "detection": {"selection": {"CommandLine": "cmd.exe"}, "condition": "selection"},
            "level": "urgent",
        }
        result = validate_sigma_rule(rule)
        self.assertTrue(result)

    def test_level_none(self):
        rule = {
            "title": "Test", "description": "Test",
            "logsource": {"product": "windows"},
            "detection": {"selection": {"CommandLine": "cmd.exe"}, "condition": "selection"},
            "level": None,
        }
        self.assertFalse(validate_sigma_rule(rule))

    def test_field_operator_validation(self):
        rule = {
            "title": "Test", "description": "Test",
            "logsource": {"product": "windows"},
            "detection": {"selection": {"CommandLine|contains": "test"}, "condition": "selection"},
            "level": "medium",
        }
        self.assertTrue(validate_sigma_rule(rule))

    def test_has_timeline_fields_detected(self):
        rule = {
            "title": "Test", "description": "Test",
            "logsource": {"product": "windows"},
            "detection": {"selection": {"EventID": "1", "CommandLine": "cmd.exe"}, "condition": "selection"},
            "level": "medium",
        }
        self.assertTrue(has_timeline_fields(rule["detection"]))

    def test_no_timeline_fields(self):
        rule = {
            "title": "Test", "description": "Test",
            "logsource": {"product": "windows"},
            "detection": {"selection": {"CommandLine": "cmd.exe"}, "condition": "selection"},
            "level": "medium",
        }
        self.assertFalse(has_timeline_fields(rule["detection"]))

    def test_detect_timeline_fields(self):
        rule = {
            "title": "Test", "description": "Test",
            "logsource": {"product": "windows"},
            "detection": {"selection": {"EventID": "1", "User": "admin"}, "condition": "selection"},
            "level": "medium",
        }
        result = detect_timeline(rule["detection"])
        self.assertTrue(result["has_timeline"])
        self.assertIn("EventID", result["fields"])
        self.assertIn("User", result["fields"])

    def test_detect_timeline_empty(self):
        rule = {
            "title": "Test", "description": "Test",
            "logsource": {"product": "windows"},
            "detection": {"selection": {"CommandLine": "cmd.exe"}, "condition": "selection"},
            "level": "medium",
        }
        result = detect_timeline(rule["detection"])
        self.assertFalse(result["has_timeline"])
        self.assertEqual(result["fields"], [])

    def test_load_sigma_rule_from_file(self):
        content = """title: Test Rule
description: Test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine: cmd.exe
    condition: selection
level: medium
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(content)
            f.flush()
            rule = load_sigma_rule(f.name)
            os.unlink(f.name)
        self.assertEqual(rule["title"], "Test Rule")
        self.assertEqual(rule["logsource"]["product"], "windows")

    def test_validate_non_dict_rule(self):
        self.assertFalse(validate_sigma_rule("not a dict"))
        self.assertFalse(validate_sigma_rule(None))
        self.assertFalse(validate_sigma_rule([]))

    def test_parse_valid_rule(self):
        content = """title: Test Parse
description: Test
logsource:
    product: windows
detection:
    selection:
        CommandLine: cmd.exe
    condition: selection
level: medium
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(content)
            f.flush()
            rule = parse_sigma_rule(f.name)
            os.unlink(f.name)
        self.assertIn("title", rule)
        self.assertIn("categories", rule)

    def test_parse_invalid_rule_missing_field(self):
        content = """title: Test
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(content)
            f.flush()
            with self.assertRaises(ValueError):
                parse_sigma_rule(f.name)
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
