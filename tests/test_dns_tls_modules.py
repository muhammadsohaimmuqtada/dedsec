import unittest
from unittest.mock import patch

from dedsec.modules import dns_recon, ssl_analysis


class DnsTlsModuleTests(unittest.TestCase):
    def test_dns_security_posture_detects_strict_policies(self):
        posture = dns_recon._security_posture(
            "example.com",
            ['v=spf1 include:_spf.example.com -all', "google-site-verification=abc"],
        )
        self.assertTrue(posture["spf"]["present"])
        self.assertTrue(posture["spf"]["strict"])

    @patch("dedsec.modules.dns_recon._resolve_records")
    def test_dns_security_posture_detects_dmarc(self, mock_resolve_records):
        mock_resolve_records.return_value = ["v=DMARC1; p=reject; rua=mailto:sec@example.com"]
        posture = dns_recon._security_posture("example.com", [])
        self.assertTrue(posture["dmarc"]["present"])
        self.assertTrue(posture["dmarc"]["strict"])

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
        mock_connect.return_value = (cert, "TLSv1.2", ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256))

        def probe_side_effect(domain, timeout, version_attr):
            if version_attr in {"TLSv1", "TLSv1_1"}:
                return {"supported": True, "status": "ok", "negotiated": "TLSv1.0"}
            return {"supported": False, "status": "blocked-or-unsupported"}

        mock_probe.side_effect = probe_side_effect

        result = ssl_analysis.run("https://example.com", "example.com")
        self.assertIn("TLSv1.0 supported", result["risks"])
        self.assertIn("TLSv1.1 supported", result["risks"])
        self.assertEqual(result["cn"], "example.com")


if __name__ == "__main__":
    unittest.main()
