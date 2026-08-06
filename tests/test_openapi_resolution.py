import unittest

from dedsec.core.api_import import OpenAPIImporter
from dedsec.core.workspace import ResearchWorkspace


class OpenAPIResolutionTests(unittest.TestCase):
    def test_local_parameter_and_schema_refs_are_resolved_into_request_surface(self):
        spec = {
            "openapi": "3.0.0",
            "servers": [
                {
                    "url": "https://{host}/api",
                    "variables": {"host": {"default": "example.com"}},
                }
            ],
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
                    "Profile": {
                        "type": "object",
                        "properties": {
                            "display_name": {"type": "string"},
                            "enabled": {"type": "boolean"},
                        },
                    }
                },
                "requestBodies": {
                    "ProfileBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Profile"}
                            }
                        }
                    }
                },
            },
            "paths": {
                "/users/{id}": {
                    "put": {
                        "parameters": [{"$ref": "#/components/parameters/UserId"}],
                        "requestBody": {"$ref": "#/components/requestBodies/ProfileBody"},
                    }
                }
            },
        }
        workspace = ResearchWorkspace("scan-ref", "https://example.com", "example.com")
        result = OpenAPIImporter("https://example.com").ingest(workspace, spec)
        self.assertEqual(result["base_url"], "https://example.com/api/")
        self.assertEqual(result["reference_warnings"], [])
        request = next(iter(workspace.requests.values()))
        self.assertEqual(request.method, "PUT")
        self.assertEqual(request.url, "https://example.com/api/users/1")
        locations = {(point.location, point.name) for point in request.insertion_points}
        self.assertIn(("path", "id"), locations)
        self.assertIn(("json", "display_name"), locations)
        self.assertIn(("json", "enabled"), locations)
        self.assertIn("state-changing-method", request.tags)
        self.assertIn("not-executed", request.tags)

    def test_external_refs_are_not_fetched_and_are_reported(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {"$ref": "https://outside.invalid/components.yaml#/UserId"}
                        ]
                    }
                }
            },
        }
        workspace = ResearchWorkspace("scan-external-ref", "https://example.com", "example.com")
        result = OpenAPIImporter("https://example.com").ingest(workspace, spec)
        self.assertTrue(
            any(item.startswith("external-reference-not-fetched:") for item in result["reference_warnings"])
        )
        request = next(iter(workspace.requests.values()))
        self.assertEqual(request.insertion_points, [])

    def test_cyclic_local_refs_are_bounded_and_do_not_recurse_forever(self):
        spec = {
            "openapi": "3.0.0",
            "components": {
                "schemas": {
                    "A": {"$ref": "#/components/schemas/B"},
                    "B": {"$ref": "#/components/schemas/A"},
                }
            },
            "paths": {
                "/cycle": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/A"}
                                }
                            }
                        }
                    }
                }
            },
        }
        workspace = ResearchWorkspace("scan-cycle", "https://example.com", "example.com")
        result = OpenAPIImporter("https://example.com").ingest(workspace, spec)
        self.assertTrue(
            any(item.startswith("cyclic-local-reference:") for item in result["reference_warnings"])
        )
        self.assertEqual(result["requests_imported"], 1)


if __name__ == "__main__":
    unittest.main()
