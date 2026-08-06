import unittest
from unittest.mock import Mock, patch

import requests

from dedsec.core.findings import VerifiedFinding
from dedsec.core.runtime import ScanContext
from dedsec.core.scope import ScopePolicy
from dedsec.core.transport import TransportEngine


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

    def test_scope_rejection_does_not_consume_budget(self):
        context = self._context()
        engine = TransportEngine(context, retries=0)
        outcome = engine.request("GET", "https://outside.test/")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.failure.category, "scope")
        self.assertEqual(context.request_budget.requests_used, 0)

    def test_budget_is_enforced(self):
        context = self._context(max_requests=0)
        engine = TransportEngine(context, retries=0)
        outcome = engine.request("GET", "https://example.com/")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.failure.category, "budget")

    @patch("requests.Session.request")
    def test_tls_failures_are_classified_without_insecure_fallback(self, request_mock):
        request_mock.side_effect = requests.exceptions.SSLError("certificate verify failed")
        engine = TransportEngine(self._context(), retries=0)
        outcome = engine.request("GET", "https://example.com/")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.failure.category, "tls")
        self.assertEqual(request_mock.call_count, 1)
        self.assertTrue(request_mock.call_args.kwargs["verify"])

    @patch("requests.Session.request")
    def test_cache_avoids_duplicate_request(self, request_mock):
        response = Mock(spec=requests.Response)
        request_mock.return_value = response
        context = self._context()
        engine = TransportEngine(context, retries=0)
        first = engine.request("GET", "https://example.com/")
        second = engine.request("GET", "https://example.com/")
        self.assertTrue(first.ok)
        self.assertTrue(second.ok)
        self.assertTrue(second.from_cache)
        self.assertEqual(request_mock.call_count, 1)
        self.assertEqual(context.request_budget.requests_used, 1)


if __name__ == "__main__":
    unittest.main()
