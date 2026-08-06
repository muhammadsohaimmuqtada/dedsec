import unittest
from unittest.mock import patch

from dedsec.modules import security_policy_audit


class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class SecurityPolicyPrecisionTests(unittest.TestCase):
    def test_google_domain_substring_is_not_policy_evidence(self):
        self.assertFalse(
            security_policy_audit._looks_like_policy(
                "/ads.txt",
                "<html><body>Visit https://google.com for search.</body></html>",
            )
        )

    def test_ads_txt_requires_structural_record(self):
        self.assertTrue(
            security_policy_audit._looks_like_policy(
                "/ads.txt",
                "example.com, publisher-123, DIRECT, cert-authority-id",
            )
        )

    def test_security_txt_requires_contact_field(self):
        self.assertFalse(
            security_policy_audit._looks_like_policy(
                "/.well-known/security.txt",
                "Expires: 2027-01-01\nCanonical: https://example.com/security.txt",
            )
        )
        self.assertTrue(
            security_policy_audit._looks_like_policy(
                "/.well-known/security.txt",
                "Contact: mailto:security@example.com\nExpires: 2027-01-01",
            )
        )

    @patch("dedsec.modules.security_policy_audit.safe_request")
    def test_generic_html_does_not_become_policy_file(self, request_mock):
        request_mock.return_value = FakeResponse(
            200,
            "<html><body>Contact our company at https://google.com</body></html>",
        )
        result = security_policy_audit.run("https://example.com", "example.com")
        self.assertEqual(result["policies_found"], [])
        self.assertFalse(result["security_txt_valid"])


if __name__ == "__main__":
    unittest.main()
