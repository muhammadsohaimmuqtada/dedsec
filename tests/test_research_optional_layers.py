import hashlib
import json
import unittest

from dedsec.core.browser import BrowserCrawler
from dedsec.core.templates import TemplateDefinition


class OptionalResearchLayerTests(unittest.TestCase):
    def test_browser_endpoint_identity_includes_scheme_host_and_effective_port(self):
        self.assertEqual(
            BrowserCrawler._endpoint("https://Example.com/path"),
            ("https", "example.com", 443),
        )
        self.assertEqual(
            BrowserCrawler._endpoint("http://example.com:8080/path"),
            ("http", "example.com", 8080),
        )
        self.assertNotEqual(
            BrowserCrawler._endpoint("https://example.com"),
            BrowserCrawler._endpoint("https://api.example.com"),
        )

    def test_browser_cookie_parser_scopes_cookie_entries_to_target_url(self):
        entries = BrowserCrawler._cookie_entries(
            "session=abc; theme=dark",
            "https://example.com/",
        )
        self.assertEqual(
            entries,
            [
                {"name": "session", "value": "abc", "url": "https://example.com/"},
                {"name": "theme", "value": "dark", "url": "https://example.com/"},
            ],
        )

    def test_template_sha256_is_integrity_check_not_classification_elevation(self):
        raw = {
            "id": "integrity-test",
            "name": "Integrity test",
            "impact": "active-safe",
            "classification": "candidate",
            "request": {"method": "GET", "path": "/"},
            "matchers": [{"type": "status", "value": 200}],
        }
        canonical = json.dumps(
            raw,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        raw["sha256"] = hashlib.sha256(canonical).hexdigest()
        definition = TemplateDefinition.from_raw(raw)
        self.assertEqual(definition.integrity, "sha256-integrity-verified")
        self.assertEqual(definition.classification, "candidate")

    def test_template_integrity_mismatch_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "integrity mismatch"):
            TemplateDefinition.from_raw(
                {
                    "id": "integrity-mismatch",
                    "name": "Mismatch",
                    "impact": "active-safe",
                    "request": {"method": "GET", "path": "/"},
                    "matchers": [{"type": "status", "value": 200}],
                    "sha256": "0" * 64,
                }
            )


if __name__ == "__main__":
    unittest.main()
