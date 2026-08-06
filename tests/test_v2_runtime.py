import sys
import time
import types
import unittest
from unittest.mock import Mock, patch

import requests

from dedsec.core.contracts import ScanConfig
from dedsec.core.findings import VerifiedFinding
from dedsec.core.orchestrator import run_modules
from dedsec.core.runtime import ScanContext
from dedsec.core.scope import ScopePolicy


class ScopePolicyTests(unittest.TestCase):
    def test_root_and_subdomains_are_allowed(self):
        policy = ScopePolicy.from_root("example.com")
        self.assertTrue(policy.check_url("https://example.com/").allowed)
        self.assertTrue(policy.check_url("https://api.example.com/v1").allowed)

    def test_unrelated_host_is_rejected(self):
        policy = ScopePolicy.from_root("example.com")
        decision = policy.check_url("https://example.net/")
        self.assertFalse(decision.allowed)
        self.assertIn("outside", decision.reason)

    def test_explicit_deny_wins(self):
        policy = ScopePolicy.from_root("example.com", denied_hosts=["admin.example.com"])
        self.assertFalse(policy.check_url("https://admin.example.com/").allowed)

    def test_port_restriction_is_enforced(self):
        policy = ScopePolicy.from_root("example.com", allowed_ports=[443])
        self.assertTrue(policy.check_url("https://example.com/").allowed)
        self.assertFalse(policy.check_url("http://example.com/").allowed)


class FindingContractTests(unittest.TestCase):
    def test_verified_findings_require_evidence(self):
        with self.assertRaises(ValueError):
            VerifiedFinding(
                source="test",
                title="Example",
                severity="high",
                verification="reproduced",
            )


class TransportTests(unittest.TestCase):
    def _context(self, max_requests=3):
        return ScanContext.build(
            target_url="https://example.com",
            domain="example.com",
            timeout=1,
            max_requests=max_requests,
        )

    def test_context_reuses_one_transport(self):
        context = self._context()
        self.assertIs(context.get_transport(retries=0), context.get_transport(retries=0))
        context.close()

    def test_scope_rejection_does_not_consume_budget(self):
        context = self._context()
        outcome = context.get_transport(retries=0).request("GET", "https://outside.test/")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.failure.category, "scope")
        self.assertEqual(context.request_budget.requests_used, 0)
        context.close()

    def test_budget_is_enforced(self):
        context = self._context(max_requests=0)
        outcome = context.get_transport(retries=0).request("GET", "https://example.com/")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.failure.category, "budget")
        context.close()

    @patch("requests.Session.request")
    def test_http_404_is_valid_transport_response(self, request_mock):
        response = Mock(spec=requests.Response)
        response.status_code = 404
        response.headers = {}
        request_mock.return_value = response
        context = self._context()
        outcome = context.get_transport(retries=0).request("GET", "https://example.com/missing")
        self.assertTrue(outcome.ok)
        self.assertIs(outcome.response, response)
        context.close()

    @patch("requests.Session.request")
    def test_tls_failures_are_classified_without_insecure_fallback(self, request_mock):
        request_mock.side_effect = requests.exceptions.SSLError("certificate verify failed")
        context = self._context()
        outcome = context.get_transport(retries=0).request("GET", "https://example.com/")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.failure.category, "tls")
        self.assertEqual(request_mock.call_count, 1)
        self.assertTrue(request_mock.call_args.kwargs["verify"])
        context.close()

    @patch("requests.Session.request")
    def test_cache_avoids_duplicate_identical_request(self, request_mock):
        response = Mock(spec=requests.Response)
        response.status_code = 200
        response.headers = {}
        request_mock.return_value = response
        context = self._context()
        engine = context.get_transport(retries=0)
        first = engine.request("GET", "https://example.com/")
        second = engine.request("GET", "https://example.com/")
        self.assertTrue(first.ok)
        self.assertTrue(second.from_cache)
        self.assertEqual(request_mock.call_count, 1)
        self.assertEqual(context.request_budget.requests_used, 1)
        context.close()

    @patch("requests.Session.request")
    def test_cache_varies_by_custom_origin_header(self, request_mock):
        response_one = Mock(spec=requests.Response)
        response_one.status_code = 200
        response_one.headers = {}
        response_two = Mock(spec=requests.Response)
        response_two.status_code = 200
        response_two.headers = {}
        request_mock.side_effect = [response_one, response_two]
        context = self._context(max_requests=5)
        engine = context.get_transport(retries=0)
        first = engine.request(
            "GET", "https://example.com/", headers={"Origin": "https://one.example"}
        )
        second = engine.request(
            "GET", "https://example.com/", headers={"Origin": "https://two.example"}
        )
        self.assertFalse(first.from_cache)
        self.assertFalse(second.from_cache)
        self.assertEqual(request_mock.call_count, 2)
        context.close()

    @patch("requests.Session.request")
    def test_retry_attempts_consume_budget_exactly(self, request_mock):
        first = Mock(spec=requests.Response)
        first.status_code = 503
        first.headers = {}
        second = Mock(spec=requests.Response)
        second.status_code = 200
        second.headers = {}
        request_mock.side_effect = [first, second]
        context = self._context(max_requests=2)
        outcome = context.get_transport(retries=1, backoff=0).request(
            "GET", "https://example.com/", cache=False
        )
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.attempts, 2)
        self.assertEqual(context.request_budget.requests_used, 2)
        context.close()

    @patch("requests.Session.request")
    def test_redirect_outside_scope_is_not_followed(self, request_mock):
        response = Mock(spec=requests.Response)
        response.status_code = 302
        response.headers = {"Location": "https://outside.test/landing"}
        request_mock.return_value = response
        context = self._context(max_requests=3)
        outcome = context.get_transport(retries=0).request(
            "GET", "https://example.com/go", allow_redirects=True, cache=False
        )
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.failure.category, "scope_redirect")
        self.assertIs(outcome.response, response)
        self.assertEqual(request_mock.call_count, 1)
        self.assertEqual(context.request_budget.requests_used, 1)
        context.close()


class RuntimeModuleCompatibilityTests(unittest.TestCase):
    def test_orchestrator_prefers_runtime_entrypoint(self):
        name = "tests.fake_runtime_module"
        module = types.ModuleType(name)

        def run_with_context(context):
            return {"entrypoint": "runtime", "scan_id": context.scan_id}

        def run(url, domain, timeout):
            raise AssertionError("legacy entrypoint should not be called")

        module.run_with_context = run_with_context
        module.run = run
        context = ScanContext.build("https://example.com", "example.com")
        with patch.dict(sys.modules, {name: module}):
            results, module_results = run_modules(
                ["fake"],
                {"fake": (name, "Fake")},
                context.target_url,
                context.domain,
                ScanConfig(concurrency=1, module_retries=0, module_timeout=2, global_timeout=3),
                scan_context=context,
            )
        self.assertEqual(results["fake"]["entrypoint"], "runtime")
        self.assertEqual(module_results[0].status, "success")
        self.assertEqual(len(module_results[0].evidence_ids), 1)
        context.close()

    def test_module_timeout_is_a_hard_execution_boundary(self):
        name = "tests.fake_hanging_module"
        module = types.ModuleType(name)

        def run(url, domain, timeout):
            time.sleep(5)
            return {"late": True}

        module.run = run
        started = time.monotonic()
        with patch.dict(sys.modules, {name: module}):
            results, module_results = run_modules(
                ["slow"],
                {"slow": (name, "Slow")},
                "https://example.com",
                "example.com",
                ScanConfig(
                    concurrency=1,
                    module_retries=0,
                    module_timeout=0.15,
                    global_timeout=2,
                ),
            )
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.5)
        self.assertEqual(module_results[0].status, "timeout")
        self.assertEqual(results["slow"]["error"], "Module hard timeout exceeded")


if __name__ == "__main__":
    unittest.main()
