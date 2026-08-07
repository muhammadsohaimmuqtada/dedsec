import csv
import os
import tempfile
import unittest
from unittest.mock import patch

from dedsec.core.browser import BrowserCrawlConfig, BrowserCrawler
from dedsec.core.evidence import redact_text
from dedsec.core.exporters import export_report
from dedsec.core.plugin_manager import PluginManager
from dedsec.core.scope import ScopePolicy
from dedsec.core.workspace import ResearchWorkspace


class _BrowserContext:
    def __init__(self):
        self.scope = ScopePolicy.from_root("example.com")
        self.identity_id = "identity-test"


class ReleaseHardeningTests(unittest.TestCase):
    def test_scope_normalizes_encoded_dot_segments_before_path_policy(self):
        policy = ScopePolicy.from_root(
            "example.com",
            include_paths=["/api/*"],
            exclude_paths=["/admin/*"],
        )
        self.assertFalse(
            policy.check_url("https://example.com/api/%252e%252e/admin/users").allowed
        )

    def test_scope_rejects_invalid_configured_ports(self):
        with self.assertRaisesRegex(ValueError, "between 1 and 65535"):
            ScopePolicy.from_root("example.com", allowed_ports=[0, 443])

    def test_double_redaction_preserves_url_encoded_marker(self):
        value = "https://example.com/?token=%5BREDACTED%5D"
        self.assertEqual(redact_text(value), value)

    def test_csv_export_neutralizes_spreadsheet_formula_cells(self):
        report = {
            "target": {"url": "https://example.com"},
            "analysis": {
                "verified_findings": [
                    {
                        "id": "finding-1",
                        "classification": "verified-finding",
                        "severity": "LOW",
                        "confidence": "verified",
                        "title": "=HYPERLINK(\"https://attacker.invalid\")",
                    }
                ],
                "hypotheses": [],
            },
            "modules": [],
            "workspace": {},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = export_report(report, tmpdir, ["csv"])["csv"]
            with open(path, newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
        self.assertTrue(rows[0]["title"].startswith("'="))

    def test_export_basename_cannot_escape_output_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaisesRegex(ValueError, "path separators"):
                export_report({}, tmpdir, ["json"], basename="../outside")

    def test_external_plugin_discovery_is_disabled_by_default(self):
        manager = PluginManager()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(PluginManager.ENABLE_ENV, None)
            with patch(
                "dedsec.core.plugin_manager.importlib_metadata.entry_points",
                side_effect=AssertionError("entry points must not be enumerated"),
            ):
                self.assertEqual(manager.discover_entry_points(), 0)
        self.assertEqual(manager.get_registered_plugins(), {})

    def test_browser_policy_blocks_scope_and_mutating_methods_before_send(self):
        crawler = BrowserCrawler(
            _BrowserContext(),
            ResearchWorkspace("scan-browser-policy", "https://example.com", "example.com"),
            BrowserCrawlConfig(),
        )
        self.assertEqual(
            crawler._request_policy("https://outside.invalid/", "GET"),
            "scope",
        )
        self.assertEqual(
            crawler._request_policy("https://example.com/api/change", "POST"),
            "state-changing-not-executed",
        )
        self.assertIsNone(
            crawler._request_policy("https://example.com/api/read", "GET")
        )


if __name__ == "__main__":
    unittest.main()
