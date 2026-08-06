import os
import tempfile
import unittest

from dedsec.core.project_store import ProjectStore
from dedsec.core.research_pipeline import ResearchPipeline
from dedsec.core.scope import ScopePolicy
from dedsec.core.workspace import RequestRecord, ResearchWorkspace


class _ResumeContext:
    def __init__(self, scan_id="scan-new"):
        self.scan_id = scan_id
        self.target_url = "https://example.com/"
        self.domain = "example.com"
        self.timeout = 2
        self.scope = ScopePolicy.from_root("example.com")
        self.default_headers = {}
        self.identity_id = "identity-anonymous"

    def get_transport(self, *args, **kwargs):
        raise AssertionError("Passive resume test must not create HTTP transport")


class V201ResumeTests(unittest.TestCase):
    def test_resume_seeds_current_coverage_from_inherited_request_corpus(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "project.db")
            old = ResearchWorkspace("scan-old", "https://example.com", "example.com")
            old.metadata["generated_at"] = "2026-08-06T01:00:00Z"
            old.add_request(
                RequestRecord.build(
                    "GET",
                    "https://example.com/search?q=term",
                    source="crawler",
                )
            )
            with ProjectStore(path) as store:
                store.checkpoint(old)

            pipeline = ResearchPipeline(_ResumeContext())
            result = pipeline.prepare(
                project_path=path,
                resume=True,
                maximum_impact="passive",
            )
            try:
                self.assertEqual(result.metadata["resumed_from_scan_id"], "scan-old")
                self.assertEqual(result.workspace.coverage.requests_discovered, 1)
                self.assertEqual(result.workspace.coverage.insertion_points_discovered, 1)
                self.assertEqual(result.workspace.coverage.requests_audited, 0)
                self.assertNotEqual(
                    result.workspace.metadata["generated_at"],
                    "2026-08-06T01:00:00Z",
                )
                self.assertEqual(result.metadata["last_checkpoint_stage"], "prepared")
            finally:
                pipeline.finalize()

    def test_resume_without_checkpoint_starts_clean_current_workspace(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "project.db")
            pipeline = ResearchPipeline(_ResumeContext("scan-clean"))
            result = pipeline.prepare(
                project_path=path,
                resume=True,
                maximum_impact="passive",
            )
            try:
                self.assertNotIn("resumed_from_scan_id", result.metadata)
                self.assertEqual(result.workspace.coverage.requests_discovered, 0)
                self.assertEqual(result.metadata["last_checkpoint_stage"], "prepared")
            finally:
                pipeline.finalize()


if __name__ == "__main__":
    unittest.main()
