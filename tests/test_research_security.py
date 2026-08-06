import unittest
from unittest.mock import patch

import requests

from dedsec.core.api_import import OpenAPIImporter
from dedsec.core.crawler import CrawlConfig, CrawlerEngine
from dedsec.core.runtime import ScanContext
from dedsec.core.templates import TemplateDefinition
from dedsec.core.workspace import (
    InsertionPoint,
    RequestRecord,
    ResearchWorkspace,
    ResponseRecord,
)


def _response(url, status=200, text="", headers=None):
    response = requests.Response()
    response.url = url
    response.status_code = status
    response.headers.update(headers or {})
    response._content = text.encode("utf-8")
    response.encoding = "utf-8"
    return response


class ResearchSecurityBoundaryTests(unittest.TestCase):
    def test_request_public_snapshot_redacts_sensitive_insertion_points_headers_and_body(self):
        request = RequestRecord.build(
            "POST",
            "https://example.com/login?token=query-secret",
            headers={
                "Authorization": "Bearer header-secret",
                "Cookie": "sid=cookie-secret",
                "X-Trace": "public-value",
            },
            body={
                "username": "researcher",
                "password": "body-secret",
                "nested": {"api_key": "api-secret"},
            },
            content_type="application/json",
        )
        public = request.public_dict()
        serialized = str(public)
        self.assertNotIn("header-secret", serialized)
        self.assertNotIn("cookie-secret", serialized)
        self.assertNotIn("query-secret", serialized)
        self.assertNotIn("body-secret", serialized)
        self.assertNotIn("api-secret", serialized)
        self.assertIn("public-value", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_response_public_snapshot_redacts_set_cookie(self):
        response = ResponseRecord.build(
            "req-1",
            "https://example.com/",
            200,
            headers={"Set-Cookie": "sid=top-secret; HttpOnly", "Server": "nginx"},
            body=b"ok",
        )
        public = response.public_dict()
        self.assertEqual(public["headers"]["Set-Cookie"], "[REDACTED]")
        self.assertEqual(public["headers"]["Server"], "nginx")

    def test_request_id_uses_surface_shape_not_secret_values(self):
        first = RequestRecord.build(
            "POST",
            "https://example.com/login?next=/a",
            body={"username": "one", "password": "secret-one"},
            content_type="application/json",
            identity_id="identity-user",
        )
        second = RequestRecord.build(
            "POST",
            "https://example.com/login?next=/b",
            body={"username": "two", "password": "secret-two"},
            content_type="application/json",
            identity_id="identity-user",
        )
        self.assertEqual(first.id, second.id)

    def test_explicit_and_inferred_insertion_points_are_merged(self):
        explicit = InsertionPoint(
            location="path",
            name="id",
            value="1",
            value_type="integer",
            required=True,
            source="openapi",
        )
        request = RequestRecord.build(
            "POST",
            "https://example.com/users/1?view=full",
            body={"profile": {"name": "sample"}},
            content_type="application/json",
            insertion_points=[explicit],
            source="openapi",
        )
        locations = {(point.location, point.name) for point in request.insertion_points}
        self.assertIn(("path", "id"), locations)
        self.assertIn(("query", "view"), locations)
        self.assertIn(("json", "profile.name"), locations)

    def test_endpoint_identity_distinguishes_method_and_ignores_query_values(self):
        workspace = ResearchWorkspace("scan-endpoint", "https://example.com", "example.com")
        workspace.add_request(RequestRecord.build("GET", "https://example.com/items?id=1"))
        workspace.add_request(RequestRecord.build("GET", "https://example.com/items?id=2"))
        workspace.add_request(RequestRecord.build("POST", "https://example.com/items"))
        endpoints = [item for item in workspace.assets.values() if item.kind == "endpoint"]
        keys = {item.key for item in endpoints}
        self.assertIn("GET https://example.com/items", keys)
        self.assertIn("POST https://example.com/items", keys)
        self.assertEqual(len(keys), 2)

    def test_duplicate_response_does_not_inflate_coverage(self):
        workspace = ResearchWorkspace("scan-response", "https://example.com", "example.com")
        response = ResponseRecord.build("req-1", "https://example.com", 200, body=b"ok")
        workspace.add_response(response)
        workspace.add_response(response)
        self.assertEqual(workspace.coverage.requests_observed, 1)

    def test_swagger_base_path_is_preserved(self):
        spec = {
            "swagger": "2.0",
            "host": "example.com",
            "basePath": "/api/v1",
            "schemes": ["https"],
            "paths": {"/users/{id}": {"get": {"parameters": [
                {"name": "id", "in": "path", "required": True, "type": "string"}
            ]}}},
        }
        workspace = ResearchWorkspace("scan-swagger", "https://example.com", "example.com")
        result = OpenAPIImporter("https://example.com").ingest(workspace, spec)
        self.assertEqual(result["base_url"], "https://example.com/api/v1/")
        request = next(iter(workspace.requests.values()))
        self.assertTrue(request.url.startswith("https://example.com/api/v1/users/"))

    def test_template_cannot_self_declare_verified_finding(self):
        with self.assertRaisesRegex(ValueError, "cannot self-verify"):
            TemplateDefinition.from_raw(
                {
                    "id": "untrusted-verified",
                    "name": "Must be rejected",
                    "classification": "verified-finding",
                    "impact": "active-safe",
                    "request": {"method": "GET", "path": "/"},
                    "matchers": [{"type": "status", "value": 200}],
                }
            )

    def test_passive_template_rejects_body_matcher_when_body_is_not_retained(self):
        with self.assertRaisesRegex(ValueError, "response bodies are not retained"):
            TemplateDefinition.from_raw(
                {
                    "id": "passive-body",
                    "name": "Unsupported body match",
                    "mode": "passive",
                    "impact": "passive",
                    "matchers": [{"type": "word", "value": "secret"}],
                }
            )

    def test_default_credentials_are_origin_bound(self):
        context = ScanContext.build(
            "https://example.com",
            "example.com",
            default_headers={
                "Authorization": "Bearer secret",
                "Cookie": "sid=secret-cookie",
            },
        )
        transport = context.get_transport(retries=0)
        with patch.object(
            transport._session,
            "request",
            side_effect=[
                _response("https://example.com/", headers={"Location": "https://api.example.com/"}, status=302),
                _response("https://api.example.com/", status=200),
            ],
        ) as request_mock:
            outcome = transport.request("GET", "https://example.com/", allow_redirects=True)
        self.assertTrue(outcome.ok)
        first_headers = request_mock.call_args_list[0].kwargs["headers"]
        second_headers = request_mock.call_args_list[1].kwargs["headers"]
        self.assertEqual(first_headers["Authorization"], "Bearer secret")
        self.assertEqual(first_headers["Cookie"], "sid=secret-cookie")
        self.assertNotIn("Authorization", second_headers)
        self.assertNotIn("Cookie", second_headers)
        context.close()

    def test_explicit_sensitive_headers_are_stripped_on_endpoint_changing_redirect(self):
        context = ScanContext.build("https://example.com", "example.com")
        transport = context.get_transport(retries=0)
        with patch.object(
            transport._session,
            "request",
            side_effect=[
                _response("https://example.com/", headers={"Location": "https://api.example.com/"}, status=302),
                _response("https://api.example.com/", status=200),
            ],
        ) as request_mock:
            outcome = transport.request(
                "GET",
                "https://example.com/",
                allow_redirects=True,
                headers={"Authorization": "Bearer explicit", "X-Trace": "safe"},
            )
        self.assertTrue(outcome.ok)
        second_headers = request_mock.call_args_list[1].kwargs["headers"]
        self.assertNotIn("Authorization", second_headers)
        self.assertEqual(second_headers["X-Trace"], "safe")
        context.close()

    def test_authenticated_crawler_corpus_stores_identity_not_credentials(self):
        context = ScanContext.build(
            "https://example.com",
            "example.com",
            default_headers={"Authorization": "Bearer secret", "Cookie": "sid=secret"},
            identity_id="identity-user",
        )
        transport = context.get_transport(retries=0)
        html = "<html><a href='/next'>next</a></html>"
        with patch.object(
            transport._session,
            "request",
            side_effect=[
                _response("https://example.com/", text=html, headers={"Content-Type": "text/html"}),
                _response("https://example.com/next", text="ok", headers={"Content-Type": "text/html"}),
            ],
        ):
            workspace = ResearchWorkspace("scan-auth-crawl", context.target_url, context.domain)
            CrawlerEngine(
                context,
                workspace,
                CrawlConfig(max_depth=1, max_pages=2),
                default_headers=context.default_headers,
            ).crawl(context.target_url)
        for request in workspace.requests.values():
            self.assertEqual(request.identity_id, "identity-user")
            self.assertFalse(any(name.lower() == "authorization" for name in request.headers))
            self.assertFalse(any(name.lower() == "cookie" for name in request.headers))
        context.close()


if __name__ == "__main__":
    unittest.main()
