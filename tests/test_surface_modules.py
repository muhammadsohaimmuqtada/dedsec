import unittest
from unittest.mock import patch

from dedsec.modules import exposure_checks, open_redirect, subdomain_enum


class FakeResponse:
    def __init__(self, status_code=200, headers=None, text="", json_data=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self._json_data = json_data

    def json(self):
        if self._json_data is not None:
            return self._json_data
        raise ValueError("No JSON available")


class SurfaceModuleTests(unittest.TestCase):
    @patch("dedsec.modules.exposure_checks.safe_request")
    def test_exposure_checks_confirm_only_with_signature(self, mock_safe_request):
        mock_safe_request.side_effect = [
            FakeResponse(status_code=200, text="hello world"),  # .env candidate only
            FakeResponse(status_code=200, text="<title>phpinfo()</title> php version 8.2"),  # confirmed
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(status_code=403, text="forbidden"),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(status_code=404, text="not found"),
        ]

        result = exposure_checks.run("https://example.com", "example.com")

        self.assertEqual(len(result["confirmed"]), 1)
        self.assertEqual(result["confirmed"][0]["id"], "phpinfo")
        self.assertGreaterEqual(len(result["candidates"]), 1)

    @patch("dedsec.modules.open_redirect.safe_request")
    def test_open_redirect_requires_control_validation(self, mock_safe_request):
        mock_safe_request.side_effect = [
            FakeResponse(status_code=302, headers={"Location": "https://evil.example"}),  # attack redirect
            FakeResponse(status_code=302, headers={"Location": "https://example.com/home"}),  # control
        ] + [FakeResponse(status_code=200, headers={}) for _ in range(len(open_redirect.REDIRECT_PARAMS) - 1)]

        result = open_redirect.run("https://example.com/login", "example.com")

        self.assertEqual(len(result["confirmed"]), 1)
        self.assertEqual(result["confirmed"][0]["param"], open_redirect.REDIRECT_PARAMS[0])

    @patch("dedsec.modules.subdomain_enum._probe_alive")
    @patch("dedsec.modules.subdomain_enum._resolve")
    @patch("dedsec.modules.subdomain_enum.safe_request")
    def test_subdomain_enum_returns_validated_results(self, mock_safe_request, mock_resolve, mock_probe_alive):
        mock_safe_request.return_value = FakeResponse(
            json_data=[
                {"name_value": "api.example.com\nwww.example.com"},
                {"name_value": "*.dev.example.com"},
            ]
        )

        def resolve_side_effect(host):
            return {"api.example.com": "1.1.1.1", "dev.example.com": "2.2.2.2"}.get(host)

        def probe_side_effect(host, timeout):
            if host == "api.example.com":
                return {"url": "https://api.example.com", "status": 200}
            return None

        mock_resolve.side_effect = resolve_side_effect
        mock_probe_alive.side_effect = probe_side_effect

        result = subdomain_enum.run("https://example.com", "example.com")

        self.assertEqual(result["discovered_count"], 2)
        self.assertEqual(result["resolved_count"], 2)
        self.assertEqual(result["alive_count"], 1)
        self.assertEqual(result["alive"][0]["subdomain"], "api.example.com")


if __name__ == "__main__":
    unittest.main()
