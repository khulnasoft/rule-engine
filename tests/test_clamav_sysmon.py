import unittest
from rule_engine.engine.parsers import parse_clamav_rule, parse_sysmon_rule, load_clamav_rule, load_sysmon_rule
from rule_engine.engine.categories import classify_rule


class TestClamAV(unittest.TestCase):

    def test_parse_clamav_rule(self):
        rule = parse_clamav_rule("rules/clamav/test.ndb")
        if isinstance(rule, list):
            self.assertGreater(len(rule), 0)
            self.assertIn("name", rule[0])
            self.assertEqual(rule[0]["name"], "Win.Executable.Malware.Generic-1234")
            self.assertEqual(rule[0]["clamav_type"], "normal")
        else:
            self.assertIn("name", rule)
            self.assertIn("clamav_type", rule)

    def test_parse_clamav_multiple(self):
        rule = parse_clamav_rule("rules/clamav/test.ndb")
        if isinstance(rule, list):
            self.assertGreater(len(rule), 1)
            names = [r["name"] for r in rule]
            self.assertIn("Win.Executable.Malware.Generic-1234", names)
            self.assertIn("Win.PE.Trojan.Generic-5678", names)
        else:
            self.assertIn(rule.get("name", ""), [
                "Win.Executable.Malware.Generic-1234",
                "Win.PE.Trojan.Generic-5678",
            ])

    def test_load_clamav_rule(self):
        rule = load_clamav_rule("rules/clamav/test.ndb")
        if isinstance(rule, list):
            self.assertGreater(len(rule), 0)
            self.assertIn("name", rule[0])
        else:
            self.assertIn("name", rule)
        self.assertIn("pattern", rule if isinstance(rule, dict) else rule[0])

    def test_clamav_type_parsing(self):
        rule = parse_clamav_rule("rules/clamav/test.ndb")
        rules = rule if isinstance(rule, list) else [rule]
        types = [r.get("clamav_type") for r in rules]
        self.assertIn("normal", types)
        self.assertIn("pe", types)


class TestSysmon(unittest.TestCase):

    def test_parse_sysmon_rule(self):
        rule = parse_sysmon_rule("rules/sysmon/test_sysmon_filter.xml")
        if isinstance(rule, list):
            self.assertGreater(len(rule), 0)
            self.assertIn("name", rule[0])
        else:
            self.assertIn("name", rule)

    def test_sysmon_event_id(self):
        rule = parse_sysmon_rule("rules/sysmon/test_sysmon_filter.xml")
        rules = rule if isinstance(rule, list) else [rule]
        event_ids = [r.get("event_id") for r in rules]
        self.assertIn("1", event_ids)
        self.assertIn("3", event_ids)

    def test_sysmon_fields(self):
        rule = parse_sysmon_rule("rules/sysmon/test_sysmon_filter.xml")
        rules = rule if isinstance(rule, list) else [rule]
        self.assertGreater(len(rules), 0)
        self.assertIn("fields", rules[0])

    def test_load_sysmon_rule(self):
        rule = load_sysmon_rule("rules/sysmon/test_sysmon_filter.xml")
        if isinstance(rule, list):
            self.assertGreater(len(rule), 0)
            self.assertIn("name", rule[0])
            self.assertIn("select", rule[0])
        else:
            self.assertIn("name", rule)
            self.assertIn("select", rule)


if __name__ == "__main__":
    unittest.main()
