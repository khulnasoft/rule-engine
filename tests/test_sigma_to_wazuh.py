import unittest
from engine.converters.sigma_to_wazuh import convert_sigma_to_wazuh
from engine.converters.sigma_to_wazuh import load_sigma_rule

class TestSigmaToWazuhConverter(unittest.TestCase):

    def test_conversion(self):
        sigma_rule = load_sigma_rule('path/to/sample_sigma_rule.yml')
        wazuh_rule = convert_sigma_to_wazuh(sigma_rule)
        expected_wazuh = """<group>
    <id>200020</id>
    <level>critical</level>
    <description>Detect virtual environment "VirtualBox|VMware|KVM|HVM"</description>
    <group>5</group>
    <classification>8</classification>
    <logsource>
        <category>process_creation</category>
        <product>windows</product>
    </logsource>
    <detection>
        <selection>
            <commandline>IlZpcnR1YWxCb3h8Vk13YXJlfEtWTXxIVk0i</commandline>
        </selection>
        <condition>selection</condition>
    </detection>
</group>"""
        self.assertEqual(wazuh_rule.strip(), expected_wazuh.strip())

    def test_invalid_conversion(self):
        with self.assertRaises(ValueError):
            convert_sigma_to_wazuh(None)

if __name__ == '__main__':
    unittest.main()
