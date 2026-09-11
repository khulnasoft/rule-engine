import unittest

from rule_engine.engine.categories import classify_rule, normalize_category
from rule_engine.engine.parsers import parse_sigma_rule


class TestCategories(unittest.TestCase):

    def test_normalize_aliases(self):
        self.assertEqual(normalize_category("web-shell"), "webshells")
        self.assertEqual(normalize_category("CVE"), "cve-rules")

    def test_classify_explicit_category_and_cve(self):
        classified = classify_rule({
            "title": "Sudo CVE-2019-14287 exploit",
            "categories": ["Malicious Documents"],
            "references": ["https://example.test/CVE-2024-12345"],
        })
        self.assertEqual(classified["primary_category"], "malicious-documents")
        self.assertIn("cve-rules", classified["categories"])
        self.assertEqual(classified["cves"], ["CVE-2019-14287", "CVE-2024-12345"])

    def test_classify_attack_tag(self):
        classified = classify_rule({"tags": ["attack.persistence", "attack.t1053"]})
        self.assertIn("persistence", classified["categories"])
        self.assertEqual(classified["category_source"]["persistence"], ["attack-tag"])

    def test_sigma_parser_exposes_categories(self):
        rule = parse_sigma_rule(
            "rules/sigma/linux/process_creation/proc_creation_lnx_sudo_cve_2019_14287.yml"
        )
        self.assertIn("cve-rules", rule["categories"])
        self.assertIn("CVE-2019-14287", rule["cves"])
        self.assertIn("primary_category", rule)


if __name__ == "__main__":
    unittest.main()