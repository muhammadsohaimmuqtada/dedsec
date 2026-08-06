import unittest

from dedsec.cli import _target_origin_scope
from dedsec.core.runtime import ScanContext
from dedsec.core.templates import TemplateDefinition, TemplateRunner
from dedsec.core.workspace import ResearchWorkspace


class _NoNetworkContext:
    def __init__(self):
        self.target_url = "https://example.com/"
        self.domain = "example.com"
        self.timeout = 1
        self.identity_id = "identity-anonymous"
        self.metadata = {"maximum_impact": "passive"}
        self.scope = type(
            "Scope",
            (),
            {"check_url": staticmethod(lambda url: type("Decision", (), {"allowed": True})())},
        )()

    def get_transport(self):
        raise AssertionError("Impact policy should skip the template before transport initialization")


class ResearchPolicyTests(unittest.TestCase):
    def test_scan_wide_impact_ceiling_is_authoritative_for_templates(self):
        context = _NoNetworkContext()
        workspace = ResearchWorkspace("scan-impact", context.target_url, context.domain)
        definition = TemplateDefinition.from_raw(
            {
                "id": "active-template",
                "name": "Active template",
                "impact": "active-safe",
                "request": {"method": "GET", "path": "/"},
                "matchers": [{"type": "status", "value": 200}],
            }
        )
        # Avoid constructing transport because the effective ceiling itself is
        # what this test targets.
        context.get_transport = lambda: type("Transport", (), {})()
        runner = TemplateRunner(context, workspace, maximum_impact="active-safe")
        result = runner.run_template(definition)
        self.assertEqual(runner.maximum_impact, "passive")
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "impact-policy")

    def test_target_origin_scope_rejects_excluded_root_host_before_preflight(self):
        context = ScanContext.build(
            "https://example.com",
            "example.com",
            allowed_hosts=["api.example.com"],
        )
        try:
            allowed, reason = _target_origin_scope(context, context.target_url)
            self.assertFalse(allowed)
            self.assertIn("not in allowed scope", reason)
        finally:
            context.close()

    def test_target_origin_scope_rejects_disallowed_port_before_preflight(self):
        context = ScanContext.build(
            "https://example.com",
            "example.com",
            allowed_ports=[80],
        )
        try:
            allowed, reason = _target_origin_scope(context, context.target_url)
            self.assertFalse(allowed)
            self.assertIn("Port 443", reason)
        finally:
            context.close()

    def test_path_rules_do_not_block_raw_target_origin_preflight(self):
        context = ScanContext.build(
            "https://example.com",
            "example.com",
            include_paths=["/api/*"],
            exclude_paths=["/api/logout"],
        )
        try:
            allowed, _ = _target_origin_scope(context, context.target_url)
            self.assertTrue(allowed)
            self.assertFalse(context.scope.check_url("https://example.com/").allowed)
            self.assertTrue(context.scope.check_url("https://example.com/api/users").allowed)
        finally:
            context.close()


if __name__ == "__main__":
    unittest.main()
