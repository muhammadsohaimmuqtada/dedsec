import unittest

from dedsec.core.browser import BrowserCrawlConfig, BrowserCrawler
from dedsec.core.scope import ScopePolicy
from dedsec.core.workspace import ResearchWorkspace


class _BrowserContext:
    def __init__(self):
        self.target_url = "https://example.com/"
        self.domain = "example.com"
        self.scope = ScopePolicy.from_root("example.com")


class V201BrowserPolicyTests(unittest.TestCase):
    def _crawler(self, allow_state_changing=False):
        context = _BrowserContext()
        return BrowserCrawler(
            context,
            ResearchWorkspace("scan-browser", context.target_url, context.domain),
            BrowserCrawlConfig(allow_state_changing_requests=allow_state_changing),
        )

    def test_out_of_scope_get_is_blocked_before_send(self):
        self.assertEqual(
            self._crawler()._request_policy("https://tracker.invalid/pixel", "GET"),
            "scope",
        )

    def test_in_scope_post_is_blocked_by_default(self):
        self.assertEqual(
            self._crawler()._request_policy("https://example.com/api/cart", "POST"),
            "state-changing-not-executed",
        )

    def test_in_scope_get_is_allowed(self):
        self.assertIsNone(
            self._crawler()._request_policy("https://example.com/app.js", "GET")
        )

    def test_explicit_config_can_allow_state_changing_browser_request(self):
        self.assertIsNone(
            self._crawler(allow_state_changing=True)._request_policy(
                "https://example.com/api/cart", "POST"
            )
        )

    def test_invalid_browser_limits_are_rejected_without_playwright(self):
        context = _BrowserContext()
        workspace = ResearchWorkspace("scan-browser-bad", context.target_url, context.domain)
        with self.assertRaisesRegex(ValueError, "max_pages"):
            BrowserCrawler(context, workspace, BrowserCrawlConfig(max_pages=0))
        with self.assertRaisesRegex(ValueError, "navigation_timeout_ms"):
            BrowserCrawler(
                context,
                workspace,
                BrowserCrawlConfig(navigation_timeout_ms=500),
            )


if __name__ == "__main__":
    unittest.main()
