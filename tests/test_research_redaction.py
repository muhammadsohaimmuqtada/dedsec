import json
import os
import tempfile
import unittest

from dedsec.core.project_store import ProjectStore
from dedsec.core.workspace import RequestRecord, ResearchWorkspace


class ResearchRedactionTests(unittest.TestCase):
    def test_sensitive_query_values_are_redacted_from_workspace_url_and_assets(self):
        workspace = ResearchWorkspace(
            "scan-query-secret",
            "https://example.com/?token=root-secret",
            "example.com",
        )
        workspace.add_request(
            RequestRecord.build(
                "GET",
                "https://example.com/reset?token=request-secret&view=public",
                source="test",
            )
        )
        snapshot = workspace.snapshot()
        serialized = json.dumps(snapshot)
        self.assertNotIn("root-secret", serialized)
        self.assertNotIn("request-secret", serialized)
        self.assertIn("%5BREDACTED%5D", serialized)
        self.assertIn("view=public", serialized)

    def test_sensitive_query_rotation_does_not_change_url_asset_identity(self):
        first = ResearchWorkspace("scan-a", "https://example.com", "example.com")
        second = ResearchWorkspace("scan-b", "https://example.com", "example.com")
        first_id = first.add_asset("url", "https://example.com/reset?token=one", source="test")
        second_id = second.add_asset("url", "https://example.com/reset?token=two", source="test")
        self.assertEqual(first_id, second_id)

    def test_sensitive_query_values_are_not_persisted_in_project_database(self):
        workspace = ResearchWorkspace("scan-db-url", "https://example.com", "example.com")
        workspace.add_request(
            RequestRecord.build(
                "GET",
                "https://example.com/callback?sessionid=database-secret",
                source="test",
            )
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "project.db")
            with ProjectStore(path) as store:
                store.save_workspace(workspace)
                loaded = store.load_scan("scan-db-url")
        serialized = json.dumps(loaded)
        self.assertNotIn("database-secret", serialized)
        self.assertIn("%5BREDACTED%5D", serialized)


if __name__ == "__main__":
    unittest.main()
