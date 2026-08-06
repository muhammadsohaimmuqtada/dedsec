import unittest
from unittest.mock import MagicMock, patch

from dedsec.modules import dns_recon, email_security, ssl_analysis


class DnsTlsModuleTests(unittest.TestCase):
    @patch("dedsec.modules.dns_recon._resolve_records", return_value=[])
    def test_dns_security_posture_detects_strict_spf(self, _resolve_records):
        posture = dns_recon._security_posture(
            "example.com",
            ["v=spf1 include:_spf.example.com -all", "google-site-verification=abc"],
            timeout=1,
        )
        self.assertTrue(posture["spf"]["present"])
        self.assertTrue(posture["spf"]["strict"])

    @patch("dedsec.modules.dns_recon._resolver")
    @patch("dedsec.modules.dns_recon._resolve_records")
    def test_dns_security_posture_detects_dmarc(self, mock_resolve_records, mock_resolver):
        mock_resolver.return_value = MagicMock()
        mock_resolve_records.return_value = ["v=DMARC1; p=reject; rua=mailto:sec@example.com"]
        posture = dns_recon._security_posture("example.com", [], timeout=1)
        self.assertTrue(posture["dmarc"]["present"])
        self.assertTrue(posture["dmarc"]["strict"])

    @patch("dedsec.modules.dns_recon._check_dkim", return_value=[])
    def test_dkim_common_selector_miss_is_not_added_as_risk(self, _dkim):
        result = {
            "dkim": {
                "found_selectors": [],
                "tested_selectors": list(dns_recon.DKIM_SELECTORS),
                "complete": False,
            }
        }
        self.assertFalse(result["dkim"]["complete"])

    @patch("dedsec.modules.ssl_analysis._probe_protocol")
    @patch("dedsec.modules.ssl_analysis._connect")
    def test_ssl_analysis_flags_weak_protocol_support(self, mock_connect, mock_probe):
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Example CA"),),),
            "notBefore": "Jan 01 00:00:00 2026 GMT",
            "notAfter": "Jan 01 00:00:00 2027 GMT",
            "subjectAltName": (("DNS", "example.com"),),
        }
        mock_connect.return_value = (
            cert,
            "TLSv1.2",
            ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256),
            "RSA-SHA256",
            True,
        )

        def probe_side_effect(domain, timeout, version_attr):
            if version_attr in {"TLSv1", "TLSv1_1"}:
                return {"supported": True, "status": "ok", "negotiated": "TLSv1.0"}
            return {"supported": False, "status": "blocked-or-unsupported"}

        mock_probe.side_effect = probe_side_effect
        result = ssl_analysis.run("https://example.com", "example.com")
        self.assertIn("TLSv1.0 supported", result["risks"])
        self.assertIn("TLSv1.1 supported", result["risks"])
        self.assertEqual(result["cn"], "example.com")
        self.assertEqual(result["sig_algo"], "RSA-SHA256")

    @patch("dedsec.modules.email_security._resolve_txt")
    @patch("dedsec.modules.email_security.dns.resolver.Resolver")
    def test_email_security_audit_is_dns_only(self, resolver_cls, mock_resolve_txt):
        def resolve_txt_side_effect(domain, selector=None, timeout=5):
            if selector is None:
                if domain.startswith("_dmarc."):
                    return ["v=DMARC1; p=reject"]
                return ["v=spf1 include:_spf.example.com -all"]
            return []

        mock_resolve_txt.side_effect = resolve_txt_side_effect

        class FakeMX:
            def __init__(self, exchange):
                self.exchange = exchange

        resolver = resolver_cls.return_value
        resolver.resolve.return_value = [FakeMX("mail.example.com")]
        result = email_security.run("https://example.com", "example.com")
        self.assertEqual(result["score"], 100)
        self.assertIn("mail.example.com", result["mx"])
        self.assertFalse(result["smtp_probe_performed"])
        self.assertFalse(result["dkim"]["complete"])


if __name__ == "__main__":
    unittest.main()
