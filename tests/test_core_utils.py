import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

import requests

from dedsec.core import utils
from dedsec.core.runtime import ScanContext


class CoreUtilsTests(unittest.TestCase):
    def tearDown(self):
        utils.unbind_scan_context()
        utils.clear_runtime_caches()

    def test_normalize_target_adds_scheme_and_domain(self):
        normalized, domain = utils.normalize_target("example.com/login?next=%2Fhome")
        self.assertEqual(normalized, "https://example.com/login?next=%2Fhome")
        self.assertEqual(domain, "example.com")

    def test_normalize_target_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            utils.normalize_target("ftp://example.com")

    @patch("dedsec.core.utils.socket.gethostbyname")
    def test_cached_resolve_ipv4_memoizes(self, mock_gethostbyname):
        mock_gethostbyname.return_value = "1.1.1.1"
        self.assertEqual(utils.cached_resolve_ipv4("example.com"), "1.1.1.1")
        self.assertEqual(utils.cached_resolve_ipv4("example.com"), "1.1.1.1")
        self.assertEqual(mock_gethostbyname.call_count, 1)

    def test_shannon_entropy(self):
        self.assertLess(utils.shannon_entropy("aaaaaaa"), 1.0)
        self.assertGreater(utils.shannon_entropy("AKIAIOSFODNN7EXAMPLE"), 3.5)

    def test_soft_404_detection(self):
        sample = "<html><head><title>Custom Page Not Found Error</title></head><body>Page not found baseline sample.</body></html>"
        profile = {"status_code": 200, "avg_length": len(sample), "sample_text": sample}

        class FakeResp:
            status_code = 200
            text = sample

        self.assertTrue(utils.is_soft_404(FakeResp(), profile))

    def test_wildcard_ip(self):
        wildcards = {"1.1.1.1", "2.2.2.2"}
        self.assertTrue(utils.is_wildcard_ip("1.1.1.1", wildcards))
        self.assertFalse(utils.is_wildcard_ip("3.3.3.3", wildcards))

    @patch("requests.Session.request")
    def test_safe_request_404_is_truthy_transport_response(self, request_mock):
        response = Mock(spec=requests.Response)
        response.status_code = 404
        response.headers = {}
        response.ok = False
        request_mock.return_value = response
        result = utils.safe_request("https://example.com/missing", cache=False)
        self.assertIsNotNone(result)
        self.assertTrue(result)
        self.assertEqual(result.status_code, 404)
        self.assertFalse(result.ok)

    def test_bound_context_fails_closed_for_unknown_external_host(self):
        context = ScanContext.build("https://example.com", "example.com", max_requests=5)
        utils.bind_scan_context(context, retries=0)
        with patch("requests.Session.request") as request_mock:
            result = utils.safe_request("https://outside.test/")
        self.assertIsNone(result)
        self.assertEqual(request_mock.call_count, 0)
        context.close()

    @patch("requests.Session.request")
    def test_bound_context_is_visible_to_module_worker_threads(self, request_mock):
        response = Mock(spec=requests.Response)
        response.status_code = 200
        response.headers = {}
        request_mock.return_value = response
        context = ScanContext.build("https://example.com", "example.com", max_requests=5)
        utils.bind_scan_context(context, retries=0)
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(
                utils.safe_request,
                "https://example.com/threaded",
                cache=False,
            ).result()
        self.assertIsNotNone(result)
        self.assertEqual(context.request_budget.requests_used, 1)
        context.close()

    @patch("requests.Session.request")
    def test_external_intelligence_allowlist_remains_accessible(self, request_mock):
        response = Mock(spec=requests.Response)
        response.status_code = 200
        response.headers = {}
        request_mock.return_value = response
        context = ScanContext.build("https://example.com", "example.com", max_requests=5)
        utils.bind_scan_context(context, retries=0)
        result = utils.safe_request("https://crt.sh/?q=example.com", cache=False)
        self.assertIsNotNone(result)
        self.assertEqual(request_mock.call_count, 1)
        self.assertEqual(context.request_budget.requests_used, 0)
        context.close()


if __name__ == "__main__":
    unittest.main()
