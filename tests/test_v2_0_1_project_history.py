import os
import tempfile
import unittest

from dedsec.core.project_store import ProjectStore
from dedsec.core.workspace import RequestRecord, ResearchWorkspace


class V201ProjectHistoryTests(unittest.TestCase):
    @staticmethod
    def _workspace(scan_id, generated_at, suffix=""):
        workspace = ResearchWorkspace(scan_id, "https://example.com", "example.com")
        workspace.metadata["generated_at"] = generated_at
        if suffix:
            workspace.add_request(
                RequestRecord.build(
                    "GET",
                    "https://example.com/%s" % suffix,
                    source="test",
                )
            )
        return workspace

    def test_diff_uses_latest_completed_scan_not_newer_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "project.db")
            with ProjectStore(path) as store:
                completed = self._workspace("scan-complete", "2026-08-06T10:00:00Z", "complete")
                store.save_workspace(completed, status="complete")

                checkpoint = self._workspace("scan-checkpoint", "2026-08-06T11:00:00Z", "checkpoint")
                store.checkpoint(checkpoint)

                current = self._workspace("scan-current", "2026-08-06T12:00:00Z", "current")
                diff = store.diff_workspace(current)

        new_urls = {
            item["url"]
            for item in diff["requests"]["new"]
            if item.get("url")
        }
        removed_urls = {
            item["url"]
            for item in diff["requests"]["removed"]
            if item.get("url")
        }
        self.assertIn("https://example.com/current", new_urls)
        self.assertIn("https://example.com/complete", removed_urls)
        self.assertNotIn("https://example.com/checkpoint", removed_urls)

    def test_latest_checkpoint_is_separate_from_completed_history(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "project.db")
            with ProjectStore(path) as store:
                completed = self._workspace("scan-complete", "2026-08-06T10:00:00Z", "complete")
                store.save_workspace(completed, status="complete")
                checkpoint = self._workspace("scan-checkpoint", "2026-08-06T11:00:00Z", "checkpoint")
                store.checkpoint(checkpoint)

                latest_complete = store.latest_workspace("example.com")
                latest_checkpoint = store.latest_checkpoint("example.com")

        self.assertEqual(latest_complete["scan_id"], "scan-complete")
        self.assertEqual(latest_checkpoint["scan_id"], "scan-checkpoint")

    def test_project_store_rejects_unknown_scan_status(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "project.db")
            workspace = self._workspace("scan-status", "2026-08-06T10:00:00Z")
            with ProjectStore(path) as store:
                with self.assertRaisesRegex(ValueError, "complete or checkpoint"):
                    store.save_workspace(workspace, status="running")

    def test_new_project_database_is_owner_only_on_posix_when_supported(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "project.db")
            with ProjectStore(path):
                pass
            if os.name == "posix":
                mode = os.stat(path).st_mode & 0o777
                self.assertEqual(mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
