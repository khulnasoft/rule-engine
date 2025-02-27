import unittest
from rule_engine.engine.converters.sigma_to_yara import convert_sigma_to_yara
from rule_engine.engine.converters.sigma_to_yara import load_sigma_rule

class TestSigmaToYaraConverter(unittest.TestCase):
    
    def test_conversion(self):
        sigma_rule = load_sigma_rule('path/to/sample_sigma_rule.yml')
        yara_rule = convert_sigma_to_yara(sigma_rule)
        expected_yara = """rule sample_rule {
    strings:
        $a = "IlZpcnR1YWxCb3h8Vk13YXJlfEtWTXxIVk0i"
    condition:
        all of them
}"""
        self.assertEqual(yara_rule, expected_yara)
    
    def test_invalid_conversion(self):
        with self.assertRaises(ValueError):
            convert_sigma_to_yara(None)

if __name__ == '__main__':
    unittest.main()
