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


if __name__ == "__main__":
    unittest.main()
