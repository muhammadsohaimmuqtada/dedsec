import errno
import unittest
from unittest.mock import patch

from dedsec.modules import api_schema_scanner, clickjacking_check, cors_check
from dedsec.modules import csp_analyzer, exposure_checks, http_methods_audit
from dedsec.modules import js_extraction, open_redirect, port_scan, rate_limit_check
from dedsec.modules import security_policy_audit, subdomain_enum, vhost_finder


class FakeResponse:
    def __init__(self, status_code=200, headers=None, text="", json_data=None, cookies=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self._json_data = json_data
        self.content = text.encode()
        self.cookies = cookies or {}

    def json(self):
        if self._json_data is not None:
            return self._json_data
        raise ValueError("No JSON available")


class SurfaceModuleTests(unittest.TestCase):
    @patch("dedsec.modules.exposure_checks.get_soft404_profile", return_value={})
    @patch("dedsec.modules.exposure_checks.safe_request")
    def test_exposure_checks_reject_signature_mismatch(self, mock_safe_request, _mock_soft404):
        responses = [
            FakeResponse(status_code=200, text="hello world"),
            FakeResponse(status_code=200, text="hello local"),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(status_code=403, text="forbidden"),
            FakeResponse(status_code=200, text="<title>phpinfo()</title> php version 8.2"),
        ]
        while len(responses) < len(exposure_checks.CHECKS):
            responses.append(FakeResponse(status_code=404, text="not found"))
        mock_safe_request.side_effect = responses

        result = exposure_checks.run("https://example.com", "example.com")
        self.assertEqual(len(result["confirmed"]), 1)
        self.assertEqual(result["confirmed"][0]["id"], "phpinfo")
        self.assertEqual(result["candidates"], [])
        rejected_ids = {item["id"] for item in result["rejected"]}
        self.assertIn("dotenv", rejected_ids)
        self.assertIn("dotenv_local", rejected_ids)
        self.assertIn("dotenv_development", rejected_ids)

    @patch("dedsec.modules.open_redirect.safe_request")
    def test_open_redirect_requires_control_validation(self, mock_safe_request):
        responses = [
            FakeResponse(status_code=200, text="landing page"),
            FakeResponse(status_code=302, headers={"Location": open_redirect.ATTACKER_URL}),
            FakeResponse(status_code=302, headers={"Location": "https://example.com/home"}),
            FakeResponse(status_code=200, text="home"),
        ]
        responses.extend(FakeResponse(status_code=200) for _ in range(200))
        mock_safe_request.side_effect = responses

        result = open_redirect.run("https://example.com/login", "example.com")
        self.assertGreaterEqual(len(result["confirmed"]), 1)
        self.assertEqual(result["confirmed"][0]["param"], "url")
        self.assertEqual(result["confirmed"][0]["location"], open_redirect.ATTACKER_URL)

    @patch("dedsec.modules.subdomain_enum.get_wildcard_ips", return_value=set())
    @patch("dedsec.modules.subdomain_enum._reverse_ip_lookup", return_value=set())
    @patch("dedsec.modules.subdomain_enum._bruteforce_subdomains", return_value=set())
    @patch("dedsec.modules.subdomain_enum._generate_permutations", return_value=set())
    @patch("dedsec.modules.subdomain_enum._fetch_hackertarget", return_value=set())
    @patch("dedsec.modules.subdomain_enum._fetch_certspotter", return_value={"stale.example.com"})
    @patch("dedsec.modules.subdomain_enum._fetch_crtsh", return_value={"api.example.com"})
    @patch("dedsec.modules.subdomain_enum._resolve")
    @patch("dedsec.modules.subdomain_enum.safe_request")
    def test_subdomain_enum_preserves_unresolved_candidates(
        self,
        mock_safe_request,
        mock_resolve,
        _crt,
        _certspotter,
        _ht,
        _perm,
        _bf,
        _reverse,
        _wildcard,
    ):
        mock_resolve.side_effect = lambda host: "1.1.1.1" if host == "api.example.com" else None
        mock_safe_request.return_value = FakeResponse(status_code=200)
        result = subdomain_enum.run("https://example.com", "example.com")
        self.assertEqual(result["discovered_count"], 2)
        self.assertEqual(result["resolved_count"], 1)
        names = {item["subdomain"] for item in result["discovered"]}
        self.assertEqual(names, {"api.example.com", "stale.example.com"})
        self.assertEqual(result["unresolved"][0]["subdomain"], "stale.example.com")

    @patch("dedsec.modules.cors_check.safe_request")
    def test_cors_reflection_with_credentials_is_candidate_not_verified(self, mock_request):
        def side_effect(url, headers=None, **kwargs):
            origin = (headers or {}).get("Origin", "")
            return FakeResponse(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                },
            )

        mock_request.side_effect = side_effect
        result = cors_check.run("https://example.com", "example.com")
        self.assertFalse(result["vulnerable"])
        self.assertTrue(result["findings"][0]["candidate"])
        self.assertFalse(result["findings"][0]["confirmed"])
        self.assertEqual(result["findings"][0]["origin"], "https://attacker.invalid")

    @patch("dedsec.modules.csp_analyzer.safe_request")
    def test_csp_analyzer_records_unsafe_directives_as_posture(self, mock_safe_request):
        mock_safe_request.return_value = FakeResponse(
            status_code=200,
            headers={
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'self' 'unsafe-inline' *"
                )
            },
        )
        result = csp_analyzer.run("https://example.com", "example.com")
        self.assertTrue(result["present"])
        self.assertIn("MEDIUM", [item["severity"] for item in result["findings"]])
        self.assertTrue(
            all(item["classification"] == "hardening-observation" for item in result["findings"])
        )

    @patch("dedsec.modules.rate_limit_check.safe_request")
    def test_rate_limit_absence_of_429_is_not_vulnerability(self, mock_request):
        mock_request.return_value = FakeResponse(status_code=200, text="Login password username")
        result = rate_limit_check.run("https://example.com", "example.com")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["assessment"], "no-throttling-observed-in-bounded-sample")
        self.assertLessEqual(result["requests_sent"], rate_limit_check.MAX_PROBES)

    @patch("dedsec.modules.clickjacking_check.safe_request")
    def test_clickjacking_missing_headers_is_frameability_observation(self, mock_safe_request):
        mock_safe_request.return_value = FakeResponse(status_code=200, headers={})
        result = clickjacking_check.run("https://example.com", "example.com")
        self.assertFalse(result["vulnerable"])
        self.assertFalse(result["protected"])
        self.assertEqual(result["observations"][0]["type"], "potential-frameability")

    @patch("dedsec.modules.vhost_finder.safe_request")
    @patch("dedsec.modules.vhost_finder.cached_resolve_ipv4", return_value="1.2.3.4")
    def test_vhost_finder_reports_unverified_response_differences(self, _resolve_ip, mock_request):
        mock_request.side_effect = [
            FakeResponse(status_code=200, text="A" * 100),
        ] + [FakeResponse(status_code=200, text="B" * 500) for _ in vhost_finder.VHOST_SUBDOMAINS]
        result = vhost_finder.run("https://example.com", "example.com")
        self.assertGreaterEqual(len(result["candidates"]), 1)
        self.assertTrue(all(item["verified"] is False for item in result["candidates"]))

    @patch("dedsec.modules.vhost_finder.safe_request", return_value=None)
    @patch("dedsec.modules.vhost_finder.cached_resolve_ipv4", return_value="1.2.3.4")
    def test_vhost_missing_baseline_is_inconclusive(self, _resolve_ip, _request):
        result = vhost_finder.run("https://example.com", "example.com")
        self.assertTrue(result["inconclusive"])
        self.assertEqual(result["transport_failures"], 1)

    @patch("dedsec.modules.api_schema_scanner.safe_request")
    def test_api_schema_scanner_dedupes_extracted_endpoints(self, mock_safe_request):
        mock_safe_request.return_value = FakeResponse(
            status_code=200,
            json_data={
                "openapi": "3.0.0",
                "info": {"title": "Test API"},
                "paths": {"/api/v1/users": {"get": {}, "post": {}}},
            },
        )
        result = api_schema_scanner.run("https://example.com", "example.com")
        self.assertGreaterEqual(len(result["schemas_found"]), 1)
        self.assertEqual(len(result["endpoints_extracted"]), 1)
        self.assertEqual(result["endpoints_extracted"][0]["methods"], ["GET", "POST"])

    @patch("dedsec.modules.http_methods_audit.safe_request")
    def test_http_methods_audit_requires_trace_echo(self, mock_safe_request):
        def side_effect(url, timeout=10, method="GET", **kwargs):
            if method == "OPTIONS":
                return FakeResponse(status_code=200, headers={"Allow": "GET,HEAD,OPTIONS"})
            if method == "TRACE":
                return FakeResponse(
                    status_code=200,
                    text="TRACE / HTTP/1.1\nX-DEDSEC-Trace-Probe: 1",
                )
            return FakeResponse(status_code=405)

        mock_safe_request.side_effect = side_effect
        result = http_methods_audit.run("https://example.com", "example.com")
        self.assertIn("HTTP TRACE echoes request data (XST-capable behavior)", result["risks"])
        self.assertFalse(result["inconclusive"])

    @patch("dedsec.modules.http_methods_audit.safe_request", return_value=None)
    def test_http_methods_audit_transport_failure_is_inconclusive(self, _request):
        result = http_methods_audit.run("https://example.com", "example.com")
        self.assertTrue(result["inconclusive"])
        self.assertEqual(result["transport_failures"], 2)
        self.assertIn("transport unavailable", result["error"].lower())

    def test_port_state_classifier_preserves_network_semantics(self):
        self.assertEqual(port_scan._classify_connect_code(0), "open")
        self.assertEqual(port_scan._classify_connect_code(errno.ECONNREFUSED), "closed")
        self.assertEqual(port_scan._classify_connect_code(errno.ETIMEDOUT), "filtered")
        self.assertEqual(port_scan._classify_connect_code(errno.EHOSTUNREACH), "unreachable")
        for name in ("EAGAIN", "EWOULDBLOCK", "EINPROGRESS", "EALREADY"):
            code = getattr(errno, name, None)
            if code is not None:
                self.assertEqual(port_scan._classify_connect_code(code), "filtered")

    @patch("dedsec.modules.security_policy_audit.safe_request")
    def test_security_policy_audit_security_txt(self, mock_safe_request):
        mock_safe_request.return_value = FakeResponse(
            status_code=200,
            text="Contact: mailto:security@example.com\nExpires: 2027-01-01",
        )
        result = security_policy_audit.run("https://example.com", "example.com")
        self.assertTrue(result["security_txt_valid"])

    def test_basic_auth_parser_rejects_google_fonts_url(self):
        content = (
            "https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&"
        )
        findings = js_extraction._scan_for_secrets(content, "page-html")
        self.assertFalse(any(item["type"] == "Basic Auth URL" for item in findings))

    def test_basic_auth_parser_accepts_structural_userinfo(self):
        findings = js_extraction._scan_for_secrets(
            "fetch('https://demo:secret@example.com/private')",
            "app.js",
        )
        self.assertTrue(any(item["type"] == "Basic Auth URL" for item in findings))


if __name__ == "__main__":
    unittest.main()
