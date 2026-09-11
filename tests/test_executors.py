import unittest
from rule_engine.engine.executors import (
    match_rule, execute_rules, get_executor,
    ClamavExecutor, SysmonExecutor,
)
from rule_engine.engine.models import RuleFormat


class TestClamavExecutor(unittest.TestCase):

    def test_match_ascii_signature(self):
        rule = {
            "name": "TestMalware",
            "format": "clamav",
            "pattern": "This is a test signature",
            "clamav_type": "normal",
        }
        self.assertTrue(match_rule(rule, "This is a test signature found in file"))
        self.assertFalse(match_rule(rule, "nothing matching here"))

    def test_match_pe_hex_signature(self):
        rule = {
            "name": "TestPE",
            "format": "clamav",
            "pattern": "4d5a",
            "clamav_type": "pe",
        }
        event = "MZ binary content"
        self.assertTrue(match_rule(rule, event))

    def test_match_hex_signature_in_bytes(self):
        rule = {
            "name": "TestHex",
            "format": "clamav",
            "pattern": "4d5a",
            "clamav_type": "pe",
        }
        event = "MZ binary content here"
        self.assertTrue(match_rule(rule, event))

    def test_no_pattern_returns_false(self):
        rule = {"name": "Empty", "format": "clamav"}
        self.assertFalse(match_rule(rule, "anything"))

    def test_clamav_type_normal(self):
        rule = {"name": "Test", "format": "clamav", "pattern": "hello", "clamav_type": "normal"}
        self.assertTrue(match_rule(rule, "say hello world"))
        self.assertFalse(match_rule(rule, "goodbye"))

    def test_executor_get(self):
        executor = get_executor("clamav")
        self.assertIsInstance(executor, ClamavExecutor)

    def test_executor_execute_rules(self):
        rules = [{"name": "Test", "format": "clamav", "pattern": "match", "clamav_type": "normal"}]
        result = execute_rules(rules, "/dev/null")
        self.assertEqual(result, [])


class TestSysmonExecutor(unittest.TestCase):

    def test_match_field_in_event(self):
        rule = {
            "name": "TestSysmon",
            "format": "sysmon",
            "event_id": "1",
            "fields": {"Image": "cmd.exe"},
        }
        event = "Image: cmd.exe executed"
        self.assertTrue(match_rule(rule, event))
        self.assertFalse(match_rule(rule, "Image: other.exe"))

    def test_match_event_id(self):
        rule = {
            "name": "Event1",
            "format": "sysmon",
            "event_id": "1",
            "fields": {"Image": "cmd.exe"},
        }
        event = "EventID: 1 Image: cmd.exe"
        self.assertTrue(match_rule(rule, event))

    def test_no_fields_returns_false(self):
        rule = {"name": "Empty", "format": "sysmon", "event_id": "1"}
        self.assertFalse(match_rule(rule, "anything"))

    def test_executor_get(self):
        executor = get_executor("sysmon")
        self.assertIsInstance(executor, SysmonExecutor)

    def test_executor_execute_rules(self):
        rules = [{"name": "Test", "format": "sysmon", "fields": {"Image": "cmd.exe"}}]
        result = execute_rules(rules, "/dev/null")
        self.assertEqual(result, [])


class TestUnifiedExecutor(unittest.TestCase):

    def test_unified_match_clamav(self):
        rule = {"name": "Test", "format": "clamav", "pattern": "virus", "clamav_type": "normal"}
        self.assertTrue(match_rule(rule, "virus detected"))

    def test_unified_match_sysmon(self):
        rule = {"name": "Test", "format": "sysmon", "fields": {"Image": "test.exe"}}
        self.assertTrue(match_rule(rule, "Image test.exe"))

    def test_unified_match_yara(self):
        rule = {"name": "Test", "format": "yara", "strings": ["malware"]}
        self.assertTrue(match_rule(rule, "malware found"))

    def test_unified_match_sigma(self):
        rule = {"name": "Test", "format": "sigma", "detection": {"selection": {"Image": "cmd.exe"}}}
        self.assertTrue(match_rule(rule, "Image: cmd.exe"))

    def test_unified_match_wazuh(self):
        rule = {"name": "Test", "format": "wazuh", "match": "alert"}
        self.assertTrue(match_rule(rule, "alert triggered"))

    def test_unified_get_all_executors(self):
        for fmt in ["yara", "sigma", "wazuh", "clamav", "sysmon"]:
            executor = get_executor(fmt)
            self.assertIsNotNone(executor, f"Failed to get executor for {fmt}")

    def test_unsupported_format_raises(self):
        with self.assertRaises(ValueError):
            get_executor("unsupported")


if __name__ == "__main__":
    unittest.main()
