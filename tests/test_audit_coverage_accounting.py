import unittest

import requests

from dedsec.core.audit import AuditConfig, AuditEngine
from dedsec.core.scope import ScopePolicy
from dedsec.core.transport import RequestOutcome
from dedsec.core.workspace import RequestRecord, ResearchWorkspace


def _response(url, text="baseline"):
    response = requests.Response()
    response.url = url
    response.status_code = 200
    response._content = text.encode("utf-8")
    response.encoding = "utf-8"
    return response


class FakeTransport:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return RequestOutcome(_response(url), None, 0.01, 1)


class FakeContext:
    def __init__(self):
        self.target_url = "https://example.com/"
        self.domain = "example.com"
        self.timeout = 2
        self.scope = ScopePolicy.from_root("example.com")
        self._transport = FakeTransport()

    def get_transport(self, *args, **kwargs):
        return self._transport


class AuditCoverageAccountingTests(unittest.TestCase):
    def _run(self, requests, max_requests=100, max_points=250):
        context = FakeContext()
        workspace = ResearchWorkspace("scan-coverage", context.target_url, context.domain)
        for request in requests:
            workspace.add_request(request)
        result = AuditEngine(
            context,
            workspace,
            AuditConfig(
                max_requests=max_requests,
                max_insertion_points=max_points,
                reflection_probe=True,
            ),
        ).run()
        return workspace, result

    def test_request_without_insertion_points_is_not_in_audit_denominator(self):
        workspace, result = self._run(
            [
                RequestRecord.build("GET", "https://example.com/", source="test"),
                RequestRecord.build(
                    "GET", "https://example.com/search?q=one", source="test"
                ),
                RequestRecord.build(
                    "GET", "https://example.com/safe?page=1", source="test"
                ),
            ]
        )

        coverage = workspace.coverage.snapshot()
        self.assertEqual(coverage["requests_discovered"], 3)
        self.assertEqual(coverage["requests_audit_eligible"], 2)
        self.assertEqual(coverage["requests_not_applicable"], 1)
        self.assertEqual(coverage["requests_audited"], 2)
        self.assertEqual(coverage["requests_skipped"], 0)
        self.assertEqual(coverage["request_audit_coverage"], 1.0)
        self.assertEqual(coverage["insertion_points_audit_eligible"], 2)
        self.assertEqual(coverage["insertion_points_audited"], 2)
        self.assertEqual(coverage["insertion_point_audit_coverage"], 1.0)
        self.assertEqual(result["requests_not_applicable"], 1)

    def test_unsupported_points_are_not_applicable_not_skipped(self):
        workspace, result = self._run(
            [
                RequestRecord.build(
                    "POST", "https://example.com/submit?q=one", source="test"
                )
            ]
        )

        coverage = workspace.coverage.snapshot()
        self.assertEqual(coverage["requests_audit_eligible"], 0)
        self.assertEqual(coverage["requests_not_applicable"], 1)
        self.assertEqual(coverage["requests_skipped"], 0)
        self.assertEqual(coverage["insertion_points_audit_eligible"], 0)
        self.assertEqual(coverage["insertion_points_not_applicable"], 1)
        self.assertEqual(
            coverage["not_applicable_reasons"].get("non-idempotent-method"), 1
        )
        self.assertEqual(result["requests_not_applicable"], 1)

    def test_request_limit_accounts_for_remaining_eligible_requests(self):
        workspace, _ = self._run(
            [
                RequestRecord.build(
                    "GET", "https://example.com/a?q=1", source="test"
                ),
                RequestRecord.build(
                    "GET", "https://example.com/b?q=1", source="test"
                ),
                RequestRecord.build(
                    "GET", "https://example.com/c?q=1", source="test"
                ),
            ],
            max_requests=1,
        )

        coverage = workspace.coverage.snapshot()
        self.assertEqual(coverage["requests_audit_eligible"], 3)
        self.assertEqual(coverage["requests_audited"], 1)
        self.assertEqual(coverage["requests_skipped"], 2)
        self.assertEqual(coverage["request_audit_coverage"], round(1 / 3, 4))
        self.assertEqual(coverage["insertion_points_audit_eligible"], 3)
        self.assertEqual(coverage["insertion_points_audited"], 1)
        self.assertEqual(coverage["insertion_points_skipped"], 2)
        self.assertEqual(coverage["skipped_reasons"].get("audit-request-limit"), 2)

    def test_point_limit_accounts_for_unprocessed_eligible_points(self):
        workspace, _ = self._run(
            [
                RequestRecord.build(
                    "GET", "https://example.com/search?a=1&b=2&c=3", source="test"
                )
            ],
            max_points=1,
        )

        coverage = workspace.coverage.snapshot()
        self.assertEqual(coverage["requests_audit_eligible"], 1)
        self.assertEqual(coverage["requests_audited"], 1)
        self.assertEqual(coverage["request_audit_coverage"], 1.0)
        self.assertEqual(coverage["insertion_points_audit_eligible"], 3)
        self.assertEqual(coverage["insertion_points_audited"], 1)
        self.assertEqual(coverage["insertion_points_skipped"], 2)
        self.assertEqual(
            coverage["insertion_point_audit_coverage"], round(1 / 3, 4)
        )
        self.assertEqual(
            coverage["skipped_reasons"].get("audit-insertion-point-limit"), 2
        )


if __name__ == "__main__":
    unittest.main()
