import os
import tempfile
import unittest

from dedsec.core.api_import import OpenAPIImporter
from dedsec.core.scan_plan import ScanPlan
from dedsec.core.scope import ScopePolicy
from dedsec.core.workspace import ResearchWorkspace


class V201SurfaceIntegrityTests(unittest.TestCase):
    def test_scope_normalizes_dot_segments_before_exclusion(self):
        scope = ScopePolicy.from_root("example.com", exclude_paths=["/admin/*"])
        self.assertFalse(scope.check_url("https://example.com/public/../admin/users").allowed)

    def test_scope_repeatedly_decodes_path_before_exclusion(self):
        scope = ScopePolicy.from_root("example.com", exclude_paths=["/admin/*"])
        self.assertFalse(scope.check_url("https://example.com/%2561dmin/users").allowed)

    def test_scope_rejects_invalid_configured_port(self):
        with self.assertRaisesRegex(ValueError, "between 1 and 65535"):
            ScopePolicy.from_root("example.com", allowed_ports=[443, 70000])

    def test_scan_plan_rejects_unknown_keys_instead_of_ignoring_typos(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "plan.yml")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "target: https://example.com\n"
                    "traffic:\n"
                    "  max_requets: 20\n"
                )
            with self.assertRaisesRegex(ValueError, "Unknown traffic key"):
                ScanPlan.load(path)

    def test_scan_plan_resolves_artifact_paths_relative_to_plan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plan_dir = os.path.join(tmpdir, "plans")
            os.makedirs(plan_dir)
            path = os.path.join(plan_dir, "plan.yml")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "target: https://example.com\n"
                    "auth_file: auth.yml\n"
                    "discovery:\n"
                    "  api_specs: [specs/api.yml]\n"
                    "project:\n"
                    "  database: state/project.db\n"
                    "templates:\n"
                    "  directories: [templates]\n"
                    "exports:\n"
                    "  directory: reports\n"
                )
            plan = ScanPlan.load(path)
        self.assertEqual(plan.auth_file, os.path.join(plan_dir, "auth.yml"))
        self.assertEqual(plan.discovery.api_specs, [os.path.join(plan_dir, "specs", "api.yml")])
        self.assertEqual(plan.project.database, os.path.join(plan_dir, "state", "project.db"))
        self.assertEqual(plan.templates.directories, [os.path.join(plan_dir, "templates")])
        self.assertEqual(plan.exports.directory, os.path.join(plan_dir, "reports"))

    def test_scan_plan_resume_requires_database(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "plan.yml")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "target: https://example.com\n"
                    "project:\n"
                    "  resume: true\n"
                )
            with self.assertRaisesRegex(ValueError, "requires project.database"):
                ScanPlan.load(path)

    def test_openapi_local_refs_resolve_and_body_points_are_preserved(self):
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://example.com"}],
            "components": {
                "parameters": {
                    "UserId": {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                },
                "schemas": {
                    "UserCreate": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "password": {"type": "string"},
                        },
                    }
                },
                "requestBodies": {
                    "UserBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/UserCreate"}
                            }
                        }
                    }
                },
            },
            "paths": {
                "/users/{id}": {
                    "parameters": [{"$ref": "#/components/parameters/UserId"}],
                    "get": {"operationId": "getUser"},
                },
                "/users": {
                    "post": {
                        "operationId": "createUser",
                        "requestBody": {"$ref": "#/components/requestBodies/UserBody"},
                    }
                },
            },
        }
        workspace = ResearchWorkspace("scan-ref", "https://example.com", "example.com")
        result = OpenAPIImporter(
            "https://example.com", scope=ScopePolicy.from_root("example.com")
        ).ingest(workspace, spec)
        self.assertEqual(result["requests_imported"], 2)
        self.assertEqual(result["unresolved_reference_count"], 0)
        requests = {item.method: item for item in workspace.requests.values()}
        get_points = {(point.location, point.name) for point in requests["GET"].insertion_points}
        post_points = {(point.location, point.name) for point in requests["POST"].insertion_points}
        self.assertIn(("path", "id"), get_points)
        self.assertIn(("json", "name"), post_points)
        self.assertIn(("json", "password"), post_points)
        self.assertIn("state-changing-method", requests["POST"].tags)

    def test_openapi_remote_refs_are_reported_and_never_fetched(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {"$ref": "https://schemas.example.invalid/parameters.json#/UserId"}
                        ]
                    }
                }
            },
        }
        workspace = ResearchWorkspace("scan-remote-ref", "https://example.com", "example.com")
        result = OpenAPIImporter("https://example.com").ingest(workspace, spec)
        self.assertEqual(result["requests_imported"], 1)
        self.assertEqual(result["remote_references_fetched"], 0)
        self.assertEqual(result["unresolved_reference_count"], 1)
        self.assertIn("https://schemas.example.invalid/parameters.json#/UserId", result["unresolved_references"])

    def test_openapi_external_server_is_recorded_but_not_claimed_as_target_asset(self):
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.other.invalid"}],
            "paths": {"/users": {"get": {"operationId": "users"}}},
        }
        workspace = ResearchWorkspace("scan-scope", "https://example.com", "example.com")
        result = OpenAPIImporter(
            "https://example.com", scope=ScopePolicy.from_root("example.com")
        ).ingest(workspace, spec)
        self.assertEqual(result["out_of_scope_requests_recorded_not_executed"], 1)
        request = next(iter(workspace.requests.values()))
        self.assertIn("out-of-scope-spec", request.tags)
        self.assertFalse(request.metadata["scope_allowed"])
        exposes_edges = [edge for edge in workspace.edges.values() if edge.relation == "exposes_api"]
        self.assertEqual(exposes_edges, [])


if __name__ == "__main__":
    unittest.main()
