import unittest
from unittest.mock import patch

from dedsec.modules import header_audit, tech_fingerprint, waf_detect


class FakeResponse:
    def __init__(self, headers=None, cookies=None, text="", status_code=200):
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.text = text
        self.status_code = status_code


class DetectionLogicTests(unittest.TestCase):
    @patch("dedsec.modules.waf_detect.safe_request")
    def test_generic_blocking_does_not_claim_specific_waf(self, mock_safe_request):
        responses = [FakeResponse(headers={"Server": "nginx"}, text="welcome", status_code=200)]
        responses.extend(
            FakeResponse(status_code=403, text="access denied")
            for _ in waf_detect.TRIGGER_PAYLOADS
        )
        mock_safe_request.side_effect = responses

        result = waf_detect.run("https://example.com", "example.com")
        self.assertEqual(result["detected"], [])
        self.assertEqual(result["blocked_triggers"], len(waf_detect.TRIGGER_PAYLOADS))
        self.assertIsNone(result["primary"])
        self.assertTrue(result["generic_blocking"])

    @patch("dedsec.modules.waf_detect.safe_request")
    def test_cloudflare_detection_requires_vendor_specific_evidence(self, mock_safe_request):
        responses = [
            FakeResponse(
                headers={"Server": "cloudflare", "CF-Ray": "abc123"},
                cookies={"__cf_bm": "token"},
                text="welcome",
                status_code=200,
            )
        ]
        responses.extend(
            FakeResponse(status_code=403, text="attention required by cloudflare")
            for _ in waf_detect.TRIGGER_PAYLOADS
        )
        mock_safe_request.side_effect = responses

        result = waf_detect.run("https://example.com", "example.com")
        self.assertEqual(result["primary"], "Cloudflare")
        self.assertIn("Cloudflare", result["detected"])
        self.assertEqual(result["blocked_triggers"], len(waf_detect.TRIGGER_PAYLOADS))

    @patch("dedsec.modules.tech_fingerprint.safe_request")
    def test_tech_fingerprint_avoids_generic_string_false_positive(self, mock_safe_request):
        mock_safe_request.return_value = FakeResponse(
            headers={"Server": "nginx"},
            text="This page mentions react to change and vue for the view.",
            status_code=200,
        )
        result = tech_fingerprint.run("https://example.com", "example.com")
        self.assertEqual(result["js_frameworks"], [])

    @patch("dedsec.modules.tech_fingerprint.safe_request")
    def test_tech_fingerprint_reports_weighted_matches(self, mock_safe_request):
        mock_safe_request.return_value = FakeResponse(
            headers={"X-Powered-By": "Express", "Server": "nginx"},
            text='window.__NEXT_DATA__ = {}; <script src="/_next/static/chunk.js"></script>',
            status_code=200,
        )
        result = tech_fingerprint.run("https://example.com", "example.com")
        self.assertIn("Next.js", [entry["name"] for entry in result["js_frameworks"]])
        self.assertIn("Node.js", [entry["name"] for entry in result["languages"]])

    @patch("dedsec.modules.header_audit.safe_request")
    def test_header_audit_flags_weak_values_without_overweighting_optional_headers(self, mock_safe_request):
        mock_safe_request.return_value = FakeResponse(
            headers={
                "Strict-Transport-Security": "includeSubDomains",
                "X-Frame-Options": "ALLOWALL",
                "X-Content-Type-Options": "nosniff",
            },
            status_code=200,
        )
        result = header_audit.run("https://example.com", "example.com")
        self.assertIn("strict-transport-security", result["weak"])
        self.assertIn("x-frame-options", result["weak"])
        self.assertIn("x-content-type-options", result["present"])
        self.assertIn("cross-origin-opener-policy", result["optional_missing"])
        self.assertEqual(result["score"]["metric"], "weighted-header-coverage")


if __name__ == "__main__":
    unittest.main()
