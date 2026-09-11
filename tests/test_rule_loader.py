import unittest
import tempfile
import os
from rule_engine.engine.parsers.load_rules import RuleLoader
from rule_engine.engine.models import RuleFormat


class TestRuleLoader(unittest.TestCase):

    def test_init(self):
        loader = RuleLoader()
        self.assertIsNotNone(loader)
        self.assertEqual(len(loader._parsers), 5)

    def test_detect_yara(self):
        loader = RuleLoader()
        content = "rule Test { meta: description = \"test\" strings: $a = \"test\" condition: $a }"
        fmt = loader.detect_format("test.yar", content)
        self.assertEqual(fmt, RuleFormat.YARA)

    def test_detect_sigma(self):
        loader = RuleLoader()
        content = "title: Test\nlogsource:\n    product: windows\n"
        fmt = loader.detect_format("test.yml", content)
        self.assertEqual(fmt, RuleFormat.SIGMA)

    def test_detect_format_from_extension(self):
        loader = RuleLoader()
        self.assertEqual(loader.detect_format("test.yar"), RuleFormat.YARA)
        self.assertEqual(loader.detect_format("test.yml"), RuleFormat.SIGMA)
        self.assertEqual(loader.detect_format("test.ndb"), RuleFormat.CLAMAV)
        self.assertEqual(loader.detect_format("test.hdb"), RuleFormat.CLAMAV)
        self.assertEqual(loader.detect_format("test.xml"), RuleFormat.WAZUH)
        self.assertEqual(loader.detect_format("test.evtx"), RuleFormat.SYSMON)

    def test_detect_unknown(self):
        loader = RuleLoader()
        self.assertIsNone(loader.detect_format("test.txt"))

    def test_load_yara(self):
        loader = RuleLoader()
        rule = loader.load("rules/yara/generic_exe2hex_payload.yar")
        self.assertIn("name", rule)
        self.assertIn("condition", rule)

    def test_load_sigma(self):
        loader = RuleLoader()
        rule = loader.load("rules/sigma/windows/process_creation/proc_creation_win_7zip_password_compression.yml")
        self.assertIn("title", rule)
        self.assertIn("detection", rule)

    def test_load_wazuh(self):
        loader = RuleLoader()
        rule = loader.load("rules/wazuh/0016-wazuh_rules.xml")
        self.assertIn("id", rule)

    def test_load_clamav(self):
        loader = RuleLoader()
        rule = loader.load("rules/clamav/test.ndb")
        if isinstance(rule, list):
            self.assertGreater(len(rule), 0)
            self.assertIn("name", rule[0])
        else:
            self.assertIn("name", rule)

    def test_load_sysmon(self):
        loader = RuleLoader()
        rule = loader.load("rules/sysmon/test_sysmon_filter.xml")
        if isinstance(rule, list):
            self.assertGreater(len(rule), 0)
            self.assertIn("name", rule[0])
        else:
            self.assertIn("name", rule)

    def test_load_by_format(self):
        loader = RuleLoader()
        rule = loader.load_by_format("rules/yara/generic_exe2hex_payload.yar", RuleFormat.YARA)
        self.assertIn("name", rule)

    def test_load_by_format_clamav(self):
        loader = RuleLoader()
        rule = loader.load_by_format("rules/clamav/test.ndb", RuleFormat.CLAMAV)
        if isinstance(rule, list):
            self.assertGreater(len(rule), 0)
        else:
            self.assertIsInstance(rule, dict)

    def test_load_directory(self):
        loader = RuleLoader()
        rules = loader.load_directory("rules/yara")
        self.assertGreater(len(rules), 0)
        self.assertIsInstance(rules, list)

    def test_load_directory_limited(self):
        loader = RuleLoader()
        rules = loader.load_directory("rules/sigma", rule_format=RuleFormat.SIGMA)
        self.assertGreater(len(rules), 0)
        for rule in rules:
            self.assertIn("title", rule)

    def test_load_unknown_raises(self):
        loader = RuleLoader()
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"test")
            f.flush()
            with self.assertRaises(ValueError):
                loader.load(f.name)
            os.unlink(f.name)

    def test_validate_sigma(self):
        loader = RuleLoader()
        valid = {
            "title": "Test",
            "description": "Test",
            "logsource": {"product": "windows"},
            "detection": {"selection": {"CommandLine": "cmd.exe"}, "condition": "selection"},
            "level": "medium",
        }
        self.assertTrue(loader.validate(valid, RuleFormat.SIGMA))

    def test_validate_invalid(self):
        loader = RuleLoader()
        self.assertFalse(loader.validate({"title": "Test"}, RuleFormat.SIGMA))

    def test_validate_non_sigma(self):
        loader = RuleLoader()
        self.assertTrue(loader.validate({"name": "test"}, RuleFormat.YARA))


if __name__ == "__main__":
    unittest.main()
