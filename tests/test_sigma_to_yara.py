import unittest
import tempfile
import os
from rule_engine.engine.converters.sigma_to_yara import convert_sigma_to_yara
from rule_engine.engine.converters.sigma_to_yara import load_sigma_rule


class TestSigmaToYaraConverter(unittest.TestCase):

    def test_conversion(self):
        sigma_content = """title: Test Rule
description: A test Sigma rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: ['test_string']
    condition: selection
level: high
id: 1001
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(sigma_content)
            f.flush()
            sigma_rule = load_sigma_rule(f.name)
            yara_rule = convert_sigma_to_yara(sigma_rule)
            os.unlink(f.name)
            self.assertIn('rule Test Rule', yara_rule)
            self.assertIn('strings:', yara_rule)
            self.assertIn('condition:', yara_rule)

    def test_invalid_conversion(self):
        with self.assertRaises((ValueError, KeyError)):
            convert_sigma_to_yara(None)

    def test_missing_detection(self):
        incomplete_rule = {'title': 'Test', 'description': 'Test'}
        result = convert_sigma_to_yara(incomplete_rule)
        self.assertIn('rule Test', result)


if __name__ == '__main__':
    unittest.main()
