import errno
import socket
import unittest
from unittest.mock import patch

from dedsec.core.network_paths import (
    NetworkPathResult,
    _state_from_errno,
    probe_target_paths,
    resolve_target_paths,
)


class V201NetworkPathTests(unittest.TestCase):
    def test_resolver_preserves_unique_ipv4_and_ipv6_addresses(self):
        answers = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.11", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::10", 443, 0, 0)),
        ]
        with patch("dedsec.core.network_paths.socket.getaddrinfo", return_value=answers):
            result = resolve_target_paths("https://example.com/")
        self.assertEqual(result["dns"], "resolved")
        self.assertEqual(
            {(item["family"], item["address"]) for item in result["addresses"]},
            {
                ("ipv4", "192.0.2.10"),
                ("ipv4", "192.0.2.11"),
                ("ipv6", "2001:db8::10"),
            },
        )

    def test_dns_failure_is_explicit_and_does_not_fabricate_paths(self):
        with patch(
            "dedsec.core.network_paths.socket.getaddrinfo",
            side_effect=socket.gaierror("no answer"),
        ):
            result = resolve_target_paths("https://example.com/")
        self.assertEqual(result["dns"], "failed")
        self.assertEqual(result["addresses"], [])
        self.assertIn("no answer", result["error"])

    def test_probe_preserves_per_address_state_and_any_reachable(self):
        resolved = {
            "host": "example.com",
            "port": 443,
            "dns": "resolved",
            "addresses": [
                {"family": "ipv4", "address": "192.0.2.10"},
                {"family": "ipv4", "address": "192.0.2.11"},
                {"family": "ipv6", "address": "2001:db8::10"},
            ],
        }

        def fake_probe(family, address, port, timeout):
            del timeout
            state = {
                "192.0.2.10": "reachable",
                "192.0.2.11": "filtered_or_timeout",
                "2001:db8::10": "unreachable",
            }[address]
            return NetworkPathResult(
                address=address,
                family="ipv6" if family == socket.AF_INET6 else "ipv4",
                port=port,
                state=state,
                error_code=0 if state == "reachable" else errno.ETIMEDOUT,
                error=None if state == "reachable" else "test",
                duration_seconds=0.001,
            )

        with patch("dedsec.core.network_paths.resolve_target_paths", return_value=resolved):
            with patch("dedsec.core.network_paths._probe_one", side_effect=fake_probe):
                result = probe_target_paths("https://example.com/", timeout=1, max_workers=3)
        self.assertTrue(result["any_reachable"])
        self.assertEqual(result["states"]["reachable"], 1)
        self.assertEqual(result["states"]["filtered_or_timeout"], 1)
        self.assertEqual(result["states"]["unreachable"], 1)
        self.assertEqual(len(result["addresses"]), 3)

    def test_errno_classifier_does_not_collapse_timeout_into_refused(self):
        self.assertEqual(_state_from_errno(0), "reachable")
        self.assertEqual(_state_from_errno(errno.ECONNREFUSED), "refused")
        self.assertEqual(_state_from_errno(errno.ETIMEDOUT), "filtered_or_timeout")
        if hasattr(errno, "ENETUNREACH"):
            self.assertEqual(_state_from_errno(errno.ENETUNREACH), "unreachable")


if __name__ == "__main__":
    unittest.main()
