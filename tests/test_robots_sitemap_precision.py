import unittest
from unittest.mock import patch

from dedsec.modules import robots_sitemap


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8")
        self.headers = headers or {}


class RobotsSitemapPrecisionTests(unittest.TestCase):
    def test_valid_urlset_is_accepted(self):
        response = FakeResponse(
            text=(
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                '<url><loc>https://example.com/</loc></url>'
                '<url><loc>https://example.com/about</loc></url>'
                '</urlset>'
            )
        )
        summary = robots_sitemap._sitemap_document_summary(response)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["type"], "urlset")
        self.assertEqual(summary["entries"], 2)

    def test_valid_sitemapindex_is_accepted(self):
        response = FakeResponse(
            text=(
                '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                '<sitemap><loc>https://example.com/sitemap-1.xml</loc></sitemap>'
                '</sitemapindex>'
            )
        )
        summary = robots_sitemap._sitemap_document_summary(response)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["type"], "sitemapindex")
        self.assertEqual(summary["entries"], 1)

    def test_html_application_shell_is_rejected(self):
        response = FakeResponse(text="<html><body><div id='root'></div></body></html>")
        self.assertIsNone(robots_sitemap._sitemap_document_summary(response))

    def test_malformed_xml_is_rejected(self):
        response = FakeResponse(text="<urlset><url><loc>https://example.com/</loc></url>")
        self.assertIsNone(robots_sitemap._sitemap_document_summary(response))

    @patch("dedsec.modules.robots_sitemap.get_soft404_profile", return_value={"status_code": 200})
    @patch("dedsec.modules.robots_sitemap.is_soft_404", return_value=False)
    @patch("dedsec.modules.robots_sitemap.safe_request")
    def test_run_accepts_only_structural_sitemaps(
        self, mock_request, _mock_soft404_check, _mock_soft404_profile
    ):
        mock_request.side_effect = [
            FakeResponse(
                text="User-agent: *\nDisallow: /private",
                headers={"content-type": "text/plain"},
            ),
            FakeResponse(text="<urlset><url><loc>https://example.com/</loc></url></urlset>"),
            FakeResponse(text="<html><body>application shell</body></html>"),
            FakeResponse(text="<urlset><url></urlset>"),
            FakeResponse(
                text=(
                    "<sitemapindex><sitemap><loc>https://example.com/s.xml</loc>"
                    "</sitemap></sitemapindex>"
                )
            ),
        ]

        result = robots_sitemap.run("https://example.com", "example.com")

        self.assertEqual(result["robots"]["disallowed"], ["/private"])
        self.assertEqual(len(result["sitemaps"]), 2)
        self.assertIn("https://example.com/sitemap.xml", result["sitemaps"])
        self.assertIn("https://example.com/wp-sitemap.xml", result["sitemaps"])

    @patch("dedsec.modules.robots_sitemap.get_soft404_profile", return_value={"status_code": 200})
    @patch("dedsec.modules.robots_sitemap.is_soft_404", return_value=True)
    @patch("dedsec.modules.robots_sitemap.safe_request")
    def test_soft404_match_wins_over_xml_shape(
        self, mock_request, _mock_soft404_check, _mock_soft404_profile
    ):
        valid_xml = "<urlset><url><loc>https://example.com/</loc></url></urlset>"
        mock_request.side_effect = [
            FakeResponse(
                text="User-agent: *\nDisallow:",
                headers={"content-type": "text/plain"},
            )
        ] + [FakeResponse(text=valid_xml) for _ in robots_sitemap.SITEMAP_PATHS]

        result = robots_sitemap.run("https://example.com", "example.com")

        self.assertEqual(result["sitemaps"], {})


if __name__ == "__main__":
    unittest.main()
