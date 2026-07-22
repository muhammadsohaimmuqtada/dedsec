import unittest
from unittest.mock import patch

from dedsec.core import utils


class CoreUtilsTests(unittest.TestCase):
    def tearDown(self):
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

        first = utils.cached_resolve_ipv4("example.com")
        second = utils.cached_resolve_ipv4("example.com")

        self.assertEqual(first, "1.1.1.1")
        self.assertEqual(second, "1.1.1.1")
        self.assertEqual(mock_gethostbyname.call_count, 1)

    def test_shannon_entropy(self):
        low_ent = utils.shannon_entropy("aaaaaaa")
        high_ent = utils.shannon_entropy("AKIAIOSFODNN7EXAMPLE")
        self.assertLess(low_ent, 1.0)
        self.assertGreater(high_ent, 3.5)

    def test_soft_404_detection(self):
        sample = "<html><head><title>Custom Page Not Found Error</title></head><body>Page not found baseline sample.</body></html>"
        profile = {
            "status_code": 200,
            "avg_length": len(sample),
            "sample_text": sample
        }
        class FakeResp:
            status_code = 200
            text = sample

        self.assertTrue(utils.is_soft_404(FakeResp(), profile))

    def test_wildcard_ip(self):
        wildcards = {"1.1.1.1", "2.2.2.2"}
        self.assertTrue(utils.is_wildcard_ip("1.1.1.1", wildcards))
        self.assertFalse(utils.is_wildcard_ip("3.3.3.3", wildcards))


if __name__ == "__main__":
    unittest.main()
