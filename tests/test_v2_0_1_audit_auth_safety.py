import unittest

from dedsec.core.api_import import OpenAPIImporter
from dedsec.core.audit import AuditConfig, AuditEngine
from dedsec.core.evidence import redact_value
from dedsec.core.scope import ScopePolicy
from dedsec.core.workspace import RequestRecord, ResearchWorkspace


class _NoRequestTransport:
    def request(self, *args, **kwargs):
        raise AssertionError("Unsafe/scope-filtered audit input must not send traffic")


class _AuditContext:
    def __init__(self):
        self.target_url = "https://example.com/"
        self.domain = "example.com"
        self.timeout = 2
        self.scope = ScopePolicy.from_root("example.com")
        self._transport = _NoRequestTransport()

    def get_transport(self, *args, **kwargs):
        return self._transport


class V201AuditAuthSafetyTests(unittest.TestCase):
    def test_openapi_identity_headers_exist_in_memory_but_redact_from_snapshot(self):
        workspace = ResearchWorkspace("scan-auth-api", "https://example.com", "example.com")
        importer = OpenAPIImporter(
            "https://example.com",
            scope=ScopePolicy.from_root("example.com"),
            default_headers={
                "Authorization": "Bearer private-token",
                "Cookie": "sid=private-session",
            },
        )
        result = importer.ingest(
            workspace,
            {
                "openapi": "3.0.0",
                "paths": {"/me": {"get": {"operationId": "me"}}},
            },
            identity_id="identity-researcher",
        )
        request = next(iter(workspace.requests.values()))
        self.assertEqual(request.identity_id, "identity-researcher")
        self.assertEqual(request.headers["Authorization"], "Bearer private-token")
        self.assertIn("private-session", request.headers["Cookie"])
        self.assertTrue(result["identity_headers_attached"])

        persisted = redact_value(workspace.snapshot())
        rendered = str(persisted)
        self.assertNotIn("private-token", rendered)
        self.assertNotIn("private-session", rendered)
        self.assertIn("[REDACTED]", rendered)

    def test_openapi_schema_header_cannot_override_researcher_auth_header(self):
        workspace = ResearchWorkspace("scan-header", "https://example.com", "example.com")
        importer = OpenAPIImporter(
            "https://example.com",
            scope=ScopePolicy.from_root("example.com"),
            default_headers={"Authorization": "Bearer configured-token"},
        )
        importer.ingest(
            workspace,
            {
                "openapi": "3.0.0",
                "paths": {
                    "/me": {
                        "get": {
                            "parameters": [
                                {
                                    "name": "Authorization",
                                    "in": "header",
                                    "schema": {"type": "string", "example": "sample-from-spec"},
                                }
                            ]
                        }
                    }
                },
            },
        )
        request = next(iter(workspace.requests.values()))
        self.assertEqual(request.headers["Authorization"], "Bearer configured-token")

    def test_audit_skips_logout_like_get_without_transport(self):
        context = _AuditContext()
        workspace = ResearchWorkspace("scan-logout", context.target_url, context.domain)
        request = RequestRecord.build("GET", "https://example.com/logout?next=/")
        workspace.add_request(request)
        result = AuditEngine(context, workspace).run([request])
        self.assertEqual(result["outcomes"].get("skipped"), 1)
        self.assertEqual(result["details"][0]["reason"], "mutation-like-path")

    def test_audit_skips_sensitive_query_token_without_transport(self):
        context = _AuditContext()
        workspace = ResearchWorkspace("scan-token", context.target_url, context.domain)
        request = RequestRecord.build("GET", "https://example.com/confirm?token=secret")
        workspace.add_request(request)
        result = AuditEngine(context, workspace).run([request])
        self.assertEqual(result["outcomes"].get("skipped"), 1)
        self.assertIn(result["details"][0]["reason"], {"mutation-like-path", "sensitive-input"})

    def test_audit_skips_out_of_scope_request_without_transport(self):
        context = _AuditContext()
        workspace = ResearchWorkspace("scan-external", context.target_url, context.domain)
        request = RequestRecord.build("GET", "https://other.invalid/search?q=x")
        workspace.add_request(request)
        result = AuditEngine(context, workspace).run([request])
        self.assertEqual(result["outcomes"].get("skipped"), 1)
        self.assertEqual(result["details"][0]["reason"], "scope")

    def test_audit_rejects_invalid_limits(self):
        with self.assertRaisesRegex(ValueError, "max_requests"):
            AuditEngine(_AuditContext(), ResearchWorkspace("scan-a", "https://example.com", "example.com"), AuditConfig(max_requests=0))
        with self.assertRaisesRegex(ValueError, "max_insertion_points"):
            AuditEngine(_AuditContext(), ResearchWorkspace("scan-b", "https://example.com", "example.com"), AuditConfig(max_insertion_points=0))


if __name__ == "__main__":
    unittest.main()
