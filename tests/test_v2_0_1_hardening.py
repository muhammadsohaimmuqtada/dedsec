import csv
import os
import tempfile
import unittest

from dedsec.core.evidence import redact_value
from dedsec.core.exporters import export_csv, export_html, export_report
from dedsec.core.research_pipeline import ResearchPipeline
from dedsec.core.templates import TemplateDefinition


class _NoNetworkContext:
    def __init__(self):
        self.scan_id = "scan-policy"
        self.target_url = "https://example.com/"
        self.domain = "example.com"
        self.timeout = 2
        self.default_headers = {}
        self.identity_id = "identity-anonymous"

    def get_transport(self, *args, **kwargs):
        return self

    def request(self, *args, **kwargs):
        raise AssertionError("Impact policy should have prevented network execution")


class V201HardeningTests(unittest.TestCase):
    def test_semantic_insertion_point_secrets_are_redacted(self):
        payload = {
            "insertion_points": [
                {
                    "location": "json",
                    "name": "user.password",
                    "value": "secret-password",
                },
                {
                    "location": "cookie",
                    "name": "sid",
                    "value": "private-session",
                },
                {
                    "location": "header",
                    "name": "X-Api-Key",
                    "value": "private-api-key",
                },
                {
                    "location": "query",
                    "name": "search",
                    "value": "public-value",
                },
            ]
        }
        redacted = redact_value(payload)
        points = redacted["insertion_points"]
        self.assertEqual(points[0]["value"], "[REDACTED]")
        self.assertEqual(points[1]["value"], "[REDACTED]")
        self.assertEqual(points[2]["value"], "[REDACTED]")
        self.assertEqual(points[3]["value"], "public-value")

    def test_template_cannot_self_promote_to_verified_finding(self):
        with self.assertRaisesRegex(ValueError, "remain unverified"):
            TemplateDefinition.from_raw(
                {
                    "id": "self-promote",
                    "name": "Must remain unverified",
                    "classification": "verified-finding",
                    "impact": "active-safe",
                    "request": {"method": "GET", "path": "/"},
                    "matchers": [{"type": "status", "value": 200}],
                }
            )

    def test_template_rejects_unknown_impact_class(self):
        with self.assertRaisesRegex(ValueError, "impact class"):
            TemplateDefinition.from_raw(
                {
                    "id": "bad-impact",
                    "name": "Bad impact",
                    "impact": "stealth",
                    "request": {"method": "GET", "path": "/"},
                    "matchers": [{"type": "status", "value": 200}],
                }
            )

    def test_template_rejects_malformed_regex_before_execution(self):
        with self.assertRaisesRegex(ValueError, "Invalid matchers"):
            TemplateDefinition.from_raw(
                {
                    "id": "bad-regex",
                    "name": "Bad regex",
                    "impact": "active-safe",
                    "request": {"method": "GET", "path": "/"},
                    "matchers": [{"type": "regex", "pattern": "("}],
                }
            )

    def test_template_rejects_malformed_extractor_regex_before_execution(self):
        with self.assertRaisesRegex(ValueError, "Invalid extractors"):
            TemplateDefinition.from_raw(
                {
                    "id": "bad-extractor",
                    "name": "Bad extractor",
                    "impact": "active-safe",
                    "request": {"method": "GET", "path": "/"},
                    "matchers": [{"type": "status", "value": 200}],
                    "extractors": [{"name": "value", "type": "regex", "pattern": "["}],
                }
            )

    def test_passive_pipeline_policy_skips_normal_network_path_probe(self):
        result = ResearchPipeline(_NoNetworkContext()).prepare(maximum_impact="passive")
        self.assertEqual(result.metadata["network_paths"]["status"], "skipped")
        self.assertEqual(result.metadata["network_paths"]["reason"], "impact-policy")

    def test_passive_pipeline_rejects_deep_discovery(self):
        with self.assertRaisesRegex(ValueError, "require maximum impact normal"):
            ResearchPipeline(_NoNetworkContext()).prepare(
                deep=True,
                maximum_impact="passive",
            )

    def test_pipeline_template_ceiling_cannot_exceed_global_impact(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "active.yml")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "id: active-template\n"
                    "name: Active template\n"
                    "impact: active-safe\n"
                    "request:\n"
                    "  method: GET\n"
                    "  path: /\n"
                    "matchers:\n"
                    "  - type: status\n"
                    "    value: 200\n"
                )
            result = ResearchPipeline(_NoNetworkContext()).prepare(
                template_dirs=[tmpdir],
                maximum_impact="passive",
            )
        self.assertEqual(result.metadata["templates"]["counts"].get("skipped"), 1)
        self.assertEqual(result.metadata["templates"]["results"][0]["reason"], "impact-policy")

    def test_csv_export_neutralizes_spreadsheet_formula_cells(self):
        report = {
            "target": {"url": "https://example.com"},
            "analysis": {
                "verified_findings": [],
                "hypotheses": [
                    {
                        "id": "hyp-csv",
                        "classification": "hypothesis",
                        "severity": "LOW",
                        "confidence": "hypothesis",
                        "title": "=HYPERLINK(\"https://attacker.invalid\",\"x\")",
                        "url": "+cmd",
                        "module": "@formula",
                        "evidence_ids": ["-1"],
                    }
                ],
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.csv")
            export_csv(report, path)
            with open(path, newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["title"].startswith("'="))
        self.assertTrue(rows[0]["url"].startswith("'+"))
        self.assertTrue(rows[0]["module"].startswith("'@"))
        self.assertTrue(rows[0]["evidence_ids"].startswith("'-"))

    def test_export_basename_cannot_escape_output_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaisesRegex(ValueError, "path separators"):
                export_report({}, tmpdir, ["json"], basename="../escape")

    def test_html_export_escapes_untrusted_finding_text(self):
        report = {
            "scan_id": "scan-html",
            "schema_version": "3.0",
            "target": {"url": "https://example.com/<script>"},
            "summary": {},
            "workspace": {"coverage": {}},
            "analysis": {
                "verified_findings": [],
                "hypotheses": [
                    {
                        "id": "hyp-html",
                        "classification": "hypothesis",
                        "severity": "LOW",
                        "confidence": "hypothesis",
                        "title": "<script>alert(1)</script>",
                    }
                ],
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.html")
            export_html(report, path)
            with open(path, encoding="utf-8") as handle:
                output = handle.read()
        self.assertNotIn("<script>alert(1)</script>", output)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", output)


if __name__ == "__main__":
    unittest.main()
