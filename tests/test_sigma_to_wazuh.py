import unittest
import tempfile
import os
from rule_engine.engine.converters.sigma_to_wazuh import convert_sigma_to_wazuh
from rule_engine.engine.converters.sigma_to_wazuh import load_sigma_rule


class TestSigmaToWazuhConverter(unittest.TestCase):

    def test_conversion(self):
        sigma_content = """title: Detect virtual environment
description: Detect virtual environment "VirtualBox|VMware|KVM|HVM"
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: ['IlZpcnR1YWxCb3h8Vk13YXJlfEtWTXxIVk0i']
    condition: selection
level: critical
id: 200020
behaviorgroup: '5'
classification: '8'
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(sigma_content)
            f.flush()
            sigma_rule = load_sigma_rule(f.name)
            wazuh_rule = convert_sigma_to_wazuh(sigma_rule)
            os.unlink(f.name)
            self.assertIn('<group>', wazuh_rule)
            self.assertIn('<id>200020</id>', wazuh_rule)
            self.assertIn('VirtualBox', wazuh_rule)

    def test_invalid_conversion(self):
        with self.assertRaises(ValueError):
            convert_sigma_to_wazuh(None)

    def test_missing_field(self):
        incomplete_rule = {'title': 'Test', 'description': 'Test'}
        result = convert_sigma_to_wazuh(incomplete_rule)
        self.assertIn('<group>', result)


if __name__ == '__main__':
    unittest.main()
