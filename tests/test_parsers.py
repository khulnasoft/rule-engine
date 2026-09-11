import unittest
from rule_engine.engine.parsers import load_rule, parse_yara_rule, parse_sigma_rule, parse_wazuh_rule


class TestParsers(unittest.TestCase):

    def test_parse_sigma_rule(self):
        rule = parse_sigma_rule('rules/sigma/windows/process_creation/proc_creation_win_7zip_password_compression.yml')
        self.assertIn('title', rule)
        self.assertIn('description', rule)
        self.assertIn('detection', rule)
        self.assertIn('level', rule)

    def test_parse_wazuh_rule(self):
        rule = parse_wazuh_rule('rules/wazuh/0016-wazuh_rules.xml')
        self.assertIn('id', rule)
        self.assertIn('level', rule)
        self.assertIn('description', rule)

    def test_parse_yara_rule(self):
        rule = parse_yara_rule('rules/yara/generic_exe2hex_payload.yar')
        self.assertIn('name', rule)
        self.assertIn('condition', rule)

    def test_load_rule_yaml(self):
        rule = load_rule('rules/sigma/windows/process_creation/proc_creation_win_7zip_password_compression.yml')
        self.assertIn('title', rule)

    def test_load_rule_xml(self):
        rule = load_rule('rules/wazuh/0016-wazuh_rules.xml')
        self.assertIn('id', rule)

    def test_load_rule_yara(self):
        rule = load_rule('rules/yara/generic_exe2hex_payload.yar')
        self.assertIn('name', rule)

    def test_parse_rule(self):
        """Test that parse_rule works for all formats."""
        for path in [
            'rules/sigma/windows/process_creation/proc_creation_win_7zip_password_compression.yml',
            'rules/wazuh/0016-wazuh_rules.xml',
            'rules/yara/generic_exe2hex_payload.yar',
        ]:
            rule = load_rule(path)
            self.assertIsNotNone(rule)


if __name__ == '__main__':
    unittest.main()
