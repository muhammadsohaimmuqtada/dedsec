import json
import os
import sys
import tempfile
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from dedsec.core.contracts import ModuleResult, ScanConfig
from dedsec.core.correlator import FindingsCorrelator
from dedsec.core.evidence import EvidenceStore
from dedsec.core.orchestrator import PerThreadCapture, run_modules
from dedsec.core.report import build_report


class EvidenceV2Tests(unittest.TestCase):
    def test_evidence_redacts_secrets_and_persists_atomically(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = EvidenceStore(scan_id="scan-test", artifact_dir=tmpdir)
            result = ModuleResult(
                module="js",
                label="JS",
                status="success",
                duration=0.1,
                data={"authorization": "Bearer abc.def", "nested": {"api_key": "supersecret"}},
                output="token=abcdef Bearer qwerty",
            )
            record = store.persist_module_result(result)
            self.assertEqual(record.data["authorization"], "[REDACTED]")
            self.assertEqual(record.data["nested"]["api_key"], "[REDACTED]")
            self.assertNotIn("abcdef", record.output_excerpt)
            self.assertTrue(record.artifact_path)
            self.assertTrue(os.path.exists(record.artifact_path))
            with open(record.artifact_path, encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload["data"]["authorization"], "[REDACTED]")
            self.assertEqual(len(record.sha256), 64)

    def test_correlator_keeps_unproven_takeover_as_hypothesis(self):
        result = ModuleResult(
            module="subdomains",
            label="Subdomains",
            status="success",
            duration=0.1,
            data={"takeovers": [{"url": "x.example.com", "provider": "demo"}]},
            evidence_ids=["ev-1"],
        )
        correlated = FindingsCorrelator().correlate([result])
        self.assertEqual(correlated["verified_findings"], [])
        self.assertEqual(len(correlated["hypotheses"]), 1)

    def test_correlator_promotes_only_evidence_backed_confirmed_exposure(self):
        result = ModuleResult(
            module="exposures",
            label="Exposures",
            status="success",
            duration=0.1,
            data={
                "confirmed": [
                    {
                        "label": "Git HEAD exposure",
                        "severity": "CRITICAL",
                        "url": "https://example.com/.git/HEAD",
                        "evidence": "content signature match",
                    }
                ],
                "candidates": [],
            },
            evidence_ids=["ev-proof"],
        )
        correlated = FindingsCorrelator().correlate([result])
        self.assertEqual(correlated["verified_findings"][0]["evidence_ids"], ["ev-proof"])
        self.assertEqual(correlated["attack_surface_score"], 30)

    def test_thread_local_capture_keeps_worker_output_separate(self):
        class Sink:
            def write(self, value):
                return len(value)

            def flush(self):
                return None

        capture = PerThreadCapture(Sink())

        def worker(text):
            with capture.capture() as buf:
                capture.write(text)
                return buf.getvalue()

        with ThreadPoolExecutor(max_workers=2) as pool:
            values = list(pool.map(worker, ["alpha", "beta"]))
        self.assertEqual(sorted(values), ["alpha", "beta"])

    def test_orchestrator_retries_transient_failure_and_persists_evidence(self):
        name = "tests.fake_transient_module"
        module = types.ModuleType(name)
        calls = {"count": 0}

        def run(url, domain, timeout):
            calls["count"] += 1
            if calls["count"] == 1:
                return {"error": "temporary timeout"}
            return {"ok": True}

        module.run = run
        store = EvidenceStore(scan_id="scan-retry")
        with patch.dict(sys.modules, {name: module}):
            results, module_results = run_modules(
                ["fake"],
                {"fake": (name, "Fake")},
                "https://example.com",
                "example.com",
                ScanConfig(module_retries=1, backoff=0, concurrency=1),
                evidence_store=store,
            )
        self.assertEqual(results["fake"], {"ok": True})
        self.assertEqual(module_results[0].attempts, 2)
        self.assertEqual(module_results[0].status, "success")
        self.assertEqual(len(module_results[0].evidence_ids), 1)

    def test_report_preserves_negative_results_and_redacts_raw_results(self):
        store = EvidenceStore(scan_id="scan-report")
        failed = ModuleResult(
            module="dns",
            label="DNS",
            status="failed",
            duration=0.2,
            error="Authorization: secret",
            data={},
        )
        evidence = store.persist_module_result(failed)
        failed.evidence_ids.append(evidence.evidence_id)
        report = build_report(
            "https://example.com",
            "example.com",
            {"dns": {"error": "token=secret"}},
            [failed],
            store,
        )
        self.assertEqual(report["schema_version"], "2.0")
        self.assertEqual(report["summary"]["failed"], 1)
        self.assertEqual(report["analysis"]["rejected_or_unverified"][0]["source"], "dns")
        self.assertNotIn("secret", json.dumps(report).lower())


if __name__ == "__main__":
    unittest.main()
