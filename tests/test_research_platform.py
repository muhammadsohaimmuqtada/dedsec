import json
import os
import tempfile
import unittest
from unittest.mock import patch

import requests

from dedsec.core.api_import import OpenAPIImporter
from dedsec.core.audit import AuditConfig, AuditEngine
from dedsec.core.auth import AuthManager, AuthProfile
from dedsec.core.crawler import CrawlConfig, CrawlerEngine
from dedsec.core.exporters import export_report
from dedsec.core.module_registry import MODULES, module_map
from dedsec.core.orchestrator import _build_child_context, _runtime_spec
from dedsec.core.passive import PassivePipeline
from dedsec.core.plugin_manager import PluginManager
from dedsec.core.project_store import ProjectStore
from dedsec.core.report import build_report
from dedsec.core.runtime import ScanContext
from dedsec.core.scan_plan import ScanPlan, impact_allowed
from dedsec.core.scope import ScopePolicy
from dedsec.core.templates import TemplateDefinition, TemplateRunner
from dedsec.core.transport import RequestOutcome
from dedsec.core.workspace import (
    RequestRecord,
    ResearchWorkspace,
    ResponseRecord,
    canonical_url,
    infer_insertion_points,
)


def _response(url, status=200, text="", headers=None):
    response = requests.Response()
    response.url = url
    response.status_code = status
    response.headers.update(headers or {})
    response._content = text.encode("utf-8")
    response.encoding = "utf-8"
    return response


class FakeTransport:
    def __init__(self, handler=None):
        self.handler = handler
        self.calls = []
        self.cookies = {}

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if self.handler is None:
            raise AssertionError("Unexpected transport request")
        response = self.handler(method, url, kwargs)
        if isinstance(response, RequestOutcome):
            return response
        return RequestOutcome(response, None, 0.01, 1)

    def session_cookies(self):
        return dict(self.cookies)


class FakeContext:
    def __init__(self, target="https://example.com/", transport=None):
        self.target_url = target
        self.domain = "example.com"
        self.timeout = 2
        self.scope = ScopePolicy.from_root("example.com")
        self._transport = transport or FakeTransport()
        self.default_headers = {}
        self.identity_id = "identity-anonymous"

    def get_transport(self, *args, **kwargs):
        return self._transport


class ResearchPlatformTests(unittest.TestCase):
    def test_canonical_url_and_insertion_point_model(self):
        self.assertEqual(
            canonical_url("HTTPS://Example.COM:443/a?q=1#fragment"),
            "https://example.com/a?q=1",
        )
        points = infer_insertion_points(
            "POST",
            "https://example.com/api?q=one",
            headers={"Cookie": "sid=abc; theme=dark", "X-Tenant-ID": "42"},
            body={"user": {"id": 7}, "enabled": True},
            content_type="application/json",
        )
        locations = {(point.location, point.name) for point in points}
        self.assertIn(("query", "q"), locations)
        self.assertIn(("cookie", "sid"), locations)
        self.assertIn(("header", "X-Tenant-ID"), locations)
        self.assertIn(("json", "user.id"), locations)
        self.assertIn(("json", "enabled"), locations)

    def test_workspace_deduplicates_assets_requests_and_computes_diff(self):
        workspace = ResearchWorkspace("scan-new", "https://example.com", "example.com")
        first = workspace.add_asset("host", "API.Example.com.", source="dns")
        second = workspace.add_asset("host", "api.example.com", source="tls")
        self.assertEqual(first, second)
        self.assertEqual(sorted(workspace.assets[first].sources), ["dns", "tls"])
        request = RequestRecord.build("GET", "https://example.com/items?id=1", source="test")
        workspace.add_request(request)
        workspace.add_request(request)
        self.assertEqual(workspace.coverage.requests_discovered, 1)

        previous = ResearchWorkspace("scan-old", "https://example.com", "example.com")
        previous_snapshot = previous.snapshot()
        diff = workspace.diff(previous_snapshot)
        self.assertTrue(any(item["kind"] == "host" for item in diff["assets"]["new"]))
        self.assertEqual(len(diff["requests"]["new"]), 1)

    def test_scope_enforces_path_include_and_exclude_rules(self):
        scope = ScopePolicy.from_root(
            "example.com",
            include_paths=["/api/*"],
            exclude_paths=["/api/admin/*", "re:^/api/private(?:/|$)"],
        )
        self.assertTrue(scope.check_url("https://example.com/api/users").allowed)
        self.assertFalse(scope.check_url("https://example.com/").allowed)
        self.assertFalse(scope.check_url("https://example.com/api/admin/users").allowed)
        self.assertFalse(scope.check_url("https://example.com/api/private/token").allowed)

    def test_scan_plan_loads_reproducible_policy_and_validates_impact(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "plan.yml")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "target: https://example.com\n"
                    "modules: [dns, tech]\n"
                    "scope:\n"
                    "  include_paths: ['/api/*']\n"
                    "  exclude_paths: ['/api/logout']\n"
                    "discovery:\n"
                    "  enabled: true\n"
                    "  crawl_depth: 2\n"
                    "traffic:\n"
                    "  max_requests: 300\n"
                    "  maximum_impact: active-safe\n"
                    "exports:\n"
                    "  formats: [json, sarif]\n"
                )
            plan = ScanPlan.load(path)
        self.assertEqual(plan.target, "https://example.com")
        self.assertEqual(plan.discovery.crawl_depth, 2)
        self.assertEqual(plan.traffic.max_requests, 300)
        self.assertTrue(impact_allowed("normal", plan.traffic.maximum_impact))
        self.assertFalse(impact_allowed("state-changing", plan.traffic.maximum_impact))

    def test_openapi_import_builds_request_corpus_without_executing_mutations(self):
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://example.com"}],
            "components": {
                "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}
            },
            "paths": {
                "/users/{id}": {
                    "get": {
                        "operationId": "getUser",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
                            {"name": "view", "in": "query", "schema": {"type": "string", "enum": ["full"]}},
                        ],
                    },
                    "delete": {"operationId": "deleteUser"},
                },
                "/users": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"name": {"type": "string"}},
                                    }
                                }
                            }
                        }
                    }
                },
            },
        }
        workspace = ResearchWorkspace("scan-api", "https://example.com", "example.com")
        result = OpenAPIImporter("https://example.com").ingest(workspace, spec)
        self.assertEqual(result["requests_imported"], 3)
        self.assertEqual(result["state_changing_requests_recorded_not_executed"], 2)
        self.assertIn("bearerAuth", workspace.metadata["api_auth_schemes"])
        requests_by_method = {item.method: item for item in workspace.requests.values()}
        self.assertIn("state-changing-method", requests_by_method["DELETE"].tags)
        self.assertIn("not-executed", requests_by_method["POST"].tags)
        self.assertTrue(any(point.name == "id" for point in requests_by_method["GET"].insertion_points))

    def test_project_store_redacts_authentication_material_before_persistence(self):
        workspace = ResearchWorkspace("scan-secret", "https://example.com", "example.com")
        request = RequestRecord.build(
            "POST",
            "https://example.com/profile",
            headers={"Authorization": "Bearer super-secret", "Cookie": "sid=private"},
            body={"password": "secret-password", "name": "researcher"},
            content_type="application/json",
            source="auth-test",
        )
        workspace.add_request(request)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "project.db")
            with ProjectStore(path) as store:
                store.save_workspace(workspace)
                loaded = store.load_scan("scan-secret")
        serialized = json.dumps(loaded).lower()
        self.assertNotIn("super-secret", serialized)
        self.assertNotIn("sid=private", serialized)
        self.assertNotIn("secret-password", serialized)
        self.assertIn("[redacted]", serialized)

    def test_passive_template_sends_zero_network_requests(self):
        transport = FakeTransport()
        context = FakeContext(transport=transport)
        workspace = ResearchWorkspace("scan-passive", context.target_url, context.domain)
        request = RequestRecord.build("GET", context.target_url, source="crawler")
        workspace.add_request(request)
        workspace.add_response(
            ResponseRecord.build(
                request.id,
                context.target_url,
                200,
                headers={"Server": "demo"},
                body=b"body is not persisted",
            )
        )
        definition = TemplateDefinition.from_raw(
            {
                "id": "passive-server-header",
                "name": "Server header observation",
                "mode": "passive",
                "impact": "passive",
                "matchers": [{"type": "header", "name": "server", "value": "demo"}],
            }
        )
        result = TemplateRunner(context, workspace, maximum_impact="active-safe").run_template(definition)
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["network_requests"], 0)
        self.assertEqual(transport.calls, [])

    def test_state_changing_template_is_never_auto_executed(self):
        transport = FakeTransport()
        context = FakeContext(transport=transport)
        workspace = ResearchWorkspace("scan-template", context.target_url, context.domain)
        definition = TemplateDefinition.from_raw(
            {
                "id": "state-change-test",
                "name": "Mutation should not run",
                "impact": "state-changing",
                "request": {"method": "POST", "path": "/change"},
                "matchers": [{"type": "status", "value": 200}],
            }
        )
        result = TemplateRunner(context, workspace, maximum_impact="state-changing").run_template(definition)
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "state-changing-template-execution-disabled")
        self.assertEqual(transport.calls, [])

    def test_audit_reflection_requires_negative_baseline_control(self):
        def handler(method, url, kwargs):
            if "dedsec-" in url:
                marker = url.split("q=", 1)[1].split("&", 1)[0]
                return _response(url, text="reflected %s" % marker)
            return _response(url, text="baseline body")

        transport = FakeTransport(handler)
        context = FakeContext(transport=transport)
        workspace = ResearchWorkspace("scan-audit", context.target_url, context.domain)
        request = RequestRecord.build("GET", "https://example.com/search?q=hello", source="crawler")
        workspace.add_request(request)
        result = AuditEngine(
            context,
            workspace,
            AuditConfig(max_requests=10, max_insertion_points=10),
        ).run()
        self.assertEqual(result["outcomes"].get("observed"), 1)
        observations = list(workspace.observations.values())
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].classification, "surface-observation")
        self.assertEqual(observations[0].severity, "INFO")
        self.assertTrue(observations[0].evidence["control_marker_absent_in_baseline"])

    def test_authentication_is_not_verified_without_verification_rule(self):
        context = FakeContext(transport=FakeTransport())
        prepared = AuthManager(context).prepare(
            AuthProfile(label="user", kind="bearer", token="secret-token")
        )
        self.assertFalse(prepared.verified)
        self.assertFalse(prepared.identity.authenticated)
        self.assertEqual(prepared.verification["reason"], "verification-not-configured")
        self.assertTrue(prepared.headers["Authorization"].startswith("Bearer "))

    def test_authentication_verification_can_establish_identity(self):
        def handler(method, url, kwargs):
            return _response(url, status=200, text="Welcome researcher dashboard")

        context = FakeContext(transport=FakeTransport(handler))
        prepared = AuthManager(context).prepare(
            AuthProfile(
                label="user",
                kind="bearer",
                token="secret-token",
                verification={
                    "url": "/me",
                    "expect_status": 200,
                    "body_regex": "Welcome researcher",
                    "logged_out_regex": "Sign in",
                },
            )
        )
        self.assertTrue(prepared.verified)
        self.assertTrue(prepared.identity.authenticated)

    def test_crawler_records_forms_without_submitting_them_and_enforces_scope(self):
        pages = {
            "https://example.com/": _response(
                "https://example.com/",
                text=(
                    "<html><a href='/next'>next</a><a href='https://outside.invalid/x'>out</a>"
                    "<form action='/login' method='post'>"
                    "<input name='username'><input type='password' name='password'>"
                    "</form></html>"
                ),
                headers={"Content-Type": "text/html"},
            ),
            "https://example.com/next": _response(
                "https://example.com/next",
                text="<html>done</html>",
                headers={"Content-Type": "text/html"},
            ),
        }

        def handler(method, url, kwargs):
            return pages[url]

        transport = FakeTransport(handler)
        context = FakeContext(transport=transport)
        workspace = ResearchWorkspace("scan-crawl", context.target_url, context.domain)
        result = CrawlerEngine(
            context,
            workspace,
            config=CrawlConfig(max_depth=2, max_pages=10),
        ).crawl(context.target_url)
        self.assertEqual(result["pages_observed"], 2)
        self.assertEqual(result["forms_discovered"], 1)
        self.assertEqual([call[0] for call in transport.calls], ["GET", "GET"])
        forms = [item for item in workspace.requests.values() if "form" in item.tags]
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0].method, "POST")
        self.assertIn("not-submitted", forms[0].tags)
        self.assertTrue(forms[0].metadata["has_password_field"])
        self.assertFalse(any("outside.invalid" in item.url for item in workspace.requests.values()))

    def test_runtime_spec_propagates_auth_headers_identity_and_path_scope(self):
        context = ScanContext.build(
            "https://example.com",
            "example.com",
            include_paths=["/api/*"],
            exclude_paths=["/api/logout"],
            default_headers={"Authorization": "Bearer test"},
            identity_id="identity-user",
        )
        spec = _runtime_spec(context)
        child = _build_child_context(spec)
        try:
            self.assertEqual(child.default_headers["Authorization"], "Bearer test")
            self.assertEqual(child.identity_id, "identity-user")
            self.assertTrue(child.scope.check_url("https://example.com/api/users").allowed)
            self.assertFalse(child.scope.check_url("https://example.com/api/logout").allowed)
        finally:
            child.close()
            context.close()

    def test_transport_merges_default_auth_headers_with_per_request_headers(self):
        context = ScanContext.build(
            "https://example.com",
            "example.com",
            default_headers={"Authorization": "Bearer test"},
        )
        transport = context.get_transport(retries=0)
        fake = _response("https://example.com", status=200, text="ok")
        with patch.object(transport._session, "request", return_value=fake) as request_mock:
            outcome = transport.request(
                "GET",
                "https://example.com",
                headers={"Origin": "https://researcher.invalid"},
            )
        sent = request_mock.call_args.kwargs["headers"]
        self.assertEqual(sent["Authorization"], "Bearer test")
        self.assertEqual(sent["Origin"], "https://researcher.invalid")
        self.assertTrue(outcome.ok)
        context.close()

    def test_passive_pipeline_produces_observations_not_verified_findings(self):
        request = RequestRecord.build("GET", "https://example.com", source="crawler")
        response = ResponseRecord.build(
            request.id,
            "https://example.com",
            200,
            headers={"Server": "nginx", "Content-Type": "text/html"},
            body=b"<html><form><input type='password'></form></html>",
        )
        observations = PassivePipeline().analyze(
            request,
            response,
            "<html><form><input type='password'></form></html>",
        )
        self.assertTrue(observations)
        self.assertTrue(all(item.classification != "verified-finding" for item in observations))

    def test_report_schema_three_contains_workspace_coverage(self):
        workspace = ResearchWorkspace("scan-report-3", "https://example.com", "example.com")
        workspace.add_request(RequestRecord.build("GET", "https://example.com/?q=1"))
        report = build_report(
            "https://example.com",
            "example.com",
            {},
            module_results=[],
            workspace=workspace,
        )
        self.assertEqual(report["schema_version"], "3.0")
        self.assertEqual(report["summary"]["requests_discovered"], 1)
        self.assertEqual(report["summary"]["insertion_points_discovered"], 1)
        self.assertIn("coverage", report["workspace"])

    def test_exporters_write_all_supported_formats(self):
        report = {
            "schema_version": "3.0",
            "scan_id": "scan-export",
            "target": {"url": "https://example.com", "domain": "example.com"},
            "summary": {},
            "modules": [],
            "analysis": {
                "verified_findings": [],
                "hypotheses": [
                    {
                        "id": "hyp-1",
                        "title": "Candidate",
                        "severity": "LOW",
                        "confidence": "hypothesis",
                    }
                ],
            },
            "workspace": {"assets": [], "requests": [], "coverage": {}},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            outputs = export_report(
                report,
                tmpdir,
                ["json", "jsonl", "sarif", "csv", "html"],
                basename="report",
            )
            self.assertEqual(set(outputs), {"json", "jsonl", "sarif", "csv", "html"})
            self.assertTrue(all(os.path.exists(path) for path in outputs.values()))
            with open(outputs["sarif"], encoding="utf-8") as handle:
                sarif = json.load(handle)
            self.assertEqual(sarif["version"], "2.1.0")

    def test_builtin_module_registry_is_complete_and_impact_annotated(self):
        self.assertEqual(len(MODULES), 24)
        self.assertEqual(set(module_map()), set(MODULES))
        self.assertTrue(all(item.impact_class for item in MODULES.values()))
        self.assertTrue(MODULES["exposures"].requires_target_http)
        self.assertIn("tcp", MODULES["ports"].protocols)

    def test_plugin_manager_reports_invalid_plugin_instead_of_swallowing_error(self):
        manager = PluginManager()
        self.assertFalse(
            manager.register_plugin(
                "missing",
                "tests.this_module_does_not_exist",
                "Missing",
            )
        )
        self.assertEqual(len(manager.diagnostics()), 1)
        self.assertIn("ModuleNotFoundError", manager.diagnostics()[0]["error"])

    def test_template_match_is_not_automatically_a_verified_finding(self):
        transport = FakeTransport(lambda method, url, kwargs: _response(url, text="marker"))
        context = FakeContext(transport=transport)
        workspace = ResearchWorkspace("scan-template-confidence", context.target_url, context.domain)
        definition = TemplateDefinition.from_raw(
            {
                "id": "candidate-only",
                "name": "Candidate only",
                "impact": "active-safe",
                "classification": "candidate",
                "severity": "MEDIUM",
                "request": {"method": "GET", "path": "/"},
                "matchers": [{"type": "word", "value": "marker"}],
            }
        )
        result = TemplateRunner(context, workspace).run_template(definition)
        self.assertEqual(result["status"], "matched")
        observation = workspace.observations[result["observation_id"]]
        self.assertEqual(observation.classification, "candidate")
        self.assertNotEqual(observation.classification, "verified-finding")


if __name__ == "__main__":
    unittest.main()
