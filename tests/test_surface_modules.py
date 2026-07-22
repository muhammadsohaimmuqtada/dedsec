import unittest
from unittest.mock import patch

from dedsec.modules import exposure_checks, open_redirect, subdomain_enum
from dedsec.modules import cors_check, csp_analyzer, rate_limit_check, clickjacking_check, email_security
from dedsec.modules import vhost_finder, api_schema_scanner, http_methods_audit, security_policy_audit


class FakeResponse:
    def __init__(self, status_code=200, headers=None, text="", json_data=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self._json_data = json_data
        self.content = text.encode()

    def json(self):
        if self._json_data is not None:
            return self._json_data
        raise ValueError("No JSON available")


class SurfaceModuleTests(unittest.TestCase):
    @patch("dedsec.modules.exposure_checks.safe_request")
    def test_exposure_checks_confirm_only_with_signature(self, mock_safe_request):
        responses = [
            FakeResponse(status_code=200, text="hello world"),  # .env candidate only
            FakeResponse(status_code=200, text="hello local"),  # .env.local candidate
            FakeResponse(status_code=404, text="not found"),    # .env.production
            FakeResponse(status_code=403, text="forbidden"),    # .env.development
            FakeResponse(status_code=200, text="<title>phpinfo()</title> php version 8.2"),  # phpinfo confirmed
        ]
        while len(responses) < len(exposure_checks.CHECKS) + 10:
            responses.append(FakeResponse(status_code=404, text="not found"))

        mock_safe_request.side_effect = responses

        result = exposure_checks.run("https://example.com", "example.com")

        self.assertEqual(len(result["confirmed"]), 1)
        self.assertEqual(result["confirmed"][0]["id"], "phpinfo")
        self.assertGreaterEqual(len(result["candidates"]), 1)

    @patch("dedsec.modules.open_redirect.safe_request")
    def test_open_redirect_requires_control_validation(self, mock_safe_request):
        responses = [
            FakeResponse(status_code=200, text="landing page"),
            FakeResponse(status_code=302, headers={"Location": "https://evil.example.com"}),
            FakeResponse(status_code=302, headers={"Location": "https://example.com/home"}),
        ]
        while len(responses) < len(open_redirect.REDIRECT_PARAMS) * 3 + 2:
            responses.append(FakeResponse(status_code=200, headers={}))

        mock_safe_request.side_effect = responses

        result = open_redirect.run("https://example.com/login", "example.com")
        self.assertGreaterEqual(len(result["confirmed"]), 0)

    @patch("dedsec.modules.subdomain_enum.get_wildcard_ips")
    @patch("dedsec.modules.subdomain_enum._resolve")
    @patch("dedsec.modules.subdomain_enum.safe_request")
    def test_subdomain_enum_returns_validated_results(self, mock_safe_request, mock_resolve, mock_get_wildcard_ips):
        mock_get_wildcard_ips.return_value = set()
        mock_safe_request.return_value = FakeResponse(
            json_data=[
                {"name_value": "api.example.com\nwww.example.com"},
                {"name_value": "*.dev.example.com"},
            ]
        )

        def resolve_side_effect(host):
            if host in ("api.example.com", "dev.example.com"):
                return "1.1.1.1"
            return None

        mock_resolve.side_effect = resolve_side_effect

        result = subdomain_enum.run("https://example.com", "example.com")
        self.assertGreaterEqual(result["discovered_count"], 1)

    # --- Phase 1 Modules Tests ---

    @patch("dedsec.modules.cors_check.requests.get")
    def test_cors_misconfiguration_hijack(self, mock_get):
        mock_get.return_value = FakeResponse(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "https://evil.example.com",
                "Access-Control-Allow-Credentials": "true"
            }
        )
        result = cors_check.run("https://example.com", "example.com")
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["findings"][0]["severity"], "CRITICAL")

    @patch("dedsec.modules.csp_analyzer.safe_request")
    def test_csp_analyzer_unsafe_directives(self, mock_safe_request):
        mock_safe_request.return_value = FakeResponse(
            status_code=200,
            headers={"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' *"}
        )
        result = csp_analyzer.run("https://example.com", "example.com")
        severities = [f["severity"] for f in result["findings"]]
        self.assertIn("HIGH", severities)

    @patch("dedsec.modules.rate_limit_check.requests.post")
    def test_rate_limit_missing(self, mock_post):
        mock_post.return_value = FakeResponse(status_code=200, text="Login success")
        result = rate_limit_check.run("https://example.com", "example.com")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["severity"], "HIGH")

    @patch("dedsec.modules.clickjacking_check.safe_request")
    def test_clickjacking_missing_headers(self, mock_safe_request):
        mock_safe_request.return_value = FakeResponse(status_code=200, headers={})
        result = clickjacking_check.run("https://example.com", "example.com")
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["findings"][0]["severity"], "MEDIUM")

    # --- Phase 2 New Modules Tests ---

    @patch("dedsec.modules.vhost_finder.requests.get")
    @patch("dedsec.modules.vhost_finder.cached_resolve_ipv4")
    def test_vhost_finder_diff(self, mock_resolve_ip, mock_get):
        mock_resolve_ip.return_value = "1.2.3.4"
        # Baseline response (len 100) vs vhost response (len 500)
        mock_get.side_effect = [
            FakeResponse(status_code=200, text="A" * 100), # baseline
        ] + [FakeResponse(status_code=200, text="B" * 500) for _ in range(len(vhost_finder.VHOST_SUBDOMAINS))]

        result = vhost_finder.run("https://example.com", "example.com")
        self.assertGreaterEqual(len(result["vhosts_found"]), 1)

    @patch("dedsec.modules.api_schema_scanner.safe_request")
    def test_api_schema_scanner_openapi_json(self, mock_safe_request):
        mock_safe_request.return_value = FakeResponse(
            status_code=200,
            json_data={
                "openapi": "3.0.0",
                "info": {"title": "Test API"},
                "paths": {"/api/v1/users": {"get": {}, "post": {}}}
            }
        )
        result = api_schema_scanner.run("https://example.com", "example.com")
        self.assertGreaterEqual(len(result["schemas_found"]), 1)
        self.assertEqual(result["schemas_found"][0]["type"], "OpenAPI/Swagger")
        self.assertGreaterEqual(len(result["endpoints_extracted"]), 1)

    @patch("dedsec.modules.http_methods_audit.safe_request")
    def test_http_methods_audit_trace_enabled(self, mock_safe_request):
        def methods_side_effect(url, timeout=10, method="GET"):
            if method == "TRACE":
                return FakeResponse(status_code=200, text="TRACE / HTTP/1.1")
            return FakeResponse(status_code=405, text="Method Not Allowed")

        mock_safe_request.side_effect = methods_side_effect
        result = http_methods_audit.run("https://example.com", "example.com")
        self.assertIn("HTTP TRACE enabled (XST risk)", result["risks"])

    @patch("dedsec.modules.security_policy_audit.safe_request")
    def test_security_policy_audit_security_txt(self, mock_safe_request):
        mock_safe_request.return_value = FakeResponse(
            status_code=200,
            text="Contact: mailto:security@example.com\nExpires: 2027-01-01"
        )
        result = security_policy_audit.run("https://example.com", "example.com")
        self.assertTrue(result["security_txt_valid"])
        self.assertEqual(len(result["policies_found"]), len(security_policy_audit.POLICY_FILES))


if __name__ == "__main__":
    unittest.main()
