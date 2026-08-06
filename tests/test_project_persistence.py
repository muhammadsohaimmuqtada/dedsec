import os
import sqlite3
import tempfile
import unittest

from dedsec.core.project_store import ProjectStore
from dedsec.core.workspace import RequestRecord, ResearchWorkspace


class ProjectPersistenceTests(unittest.TestCase):
    def test_scan_table_never_stores_sensitive_target_query_value(self):
        workspace = ResearchWorkspace(
            "scan-target-secret",
            "https://example.com/?token=target-secret",
            "example.com",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "project.db")
            with ProjectStore(path) as store:
                store.save_workspace(workspace)
            connection = sqlite3.connect(path)
            try:
                stored = connection.execute(
                    "SELECT target_url FROM scans WHERE scan_id = ?",
                    (workspace.scan_id,),
                ).fetchone()[0]
            finally:
                connection.close()
        self.assertNotIn("target-secret", stored)
        self.assertIn("%5BREDACTED%5D", stored)

    def test_entity_tables_receive_public_redacted_request_payloads(self):
        workspace = ResearchWorkspace("scan-entity-secret", "https://example.com", "example.com")
        workspace.add_request(
            RequestRecord.build(
                "POST",
                "https://example.com/login",
                headers={"Authorization": "Bearer hidden"},
                body={"password": "body-hidden"},
                content_type="application/json",
            )
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "project.db")
            with ProjectStore(path) as store:
                store.save_workspace(workspace)
            connection = sqlite3.connect(path)
            try:
                payload = connection.execute(
                    "SELECT payload_json FROM requests WHERE scan_id = ? LIMIT 1",
                    (workspace.scan_id,),
                ).fetchone()[0]
            finally:
                connection.close()
        self.assertNotIn("Bearer hidden", payload)
        self.assertNotIn("body-hidden", payload)
        self.assertIn("REDACTED", payload)

    def test_diff_baseline_excludes_current_scan_and_uses_latest_complete(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "project.db")
            with ProjectStore(path) as store:
                first = ResearchWorkspace("scan-1", "https://example.com", "example.com")
                first.add_asset("host", "api.example.com", source="first")
                store.save_workspace(first)

                second = ResearchWorkspace("scan-2", "https://example.com", "example.com")
                second.add_asset("host", "api.example.com", source="second")
                second.add_asset("host", "new.example.com", source="second")
                diff = store.diff_workspace(second)
                self.assertEqual(diff["baseline_scan_id"], "scan-1")
                self.assertEqual(diff["current_scan_id"], "scan-2")
                new_hosts = {
                    item["key"]
                    for item in diff["assets"]["new"]
                    if item.get("kind") == "host"
                }
                self.assertIn("new.example.com", new_hosts)


if __name__ == "__main__":
    unittest.main()
