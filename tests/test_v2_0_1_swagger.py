import unittest

from dedsec.core.api_import import OpenAPIImporter
from dedsec.core.scope import ScopePolicy
from dedsec.core.workspace import ResearchWorkspace


class V201SwaggerTests(unittest.TestCase):
    def test_swagger_formdata_becomes_body_insertion_points(self):
        spec = {
            "swagger": "2.0",
            "host": "example.com",
            "basePath": "/api",
            "schemes": ["https"],
            "consumes": ["application/x-www-form-urlencoded"],
            "paths": {
                "/login": {
                    "post": {
                        "parameters": [
                            {"name": "username", "in": "formData", "type": "string", "required": True},
                            {"name": "password", "in": "formData", "type": "string", "required": True},
                        ]
                    }
                }
            },
        }
        workspace = ResearchWorkspace("scan-swagger-form", "https://example.com", "example.com")
        result = OpenAPIImporter(
            "https://example.com",
            scope=ScopePolicy.from_root("example.com"),
        ).ingest(workspace, spec)
        request = next(iter(workspace.requests.values()))
        self.assertEqual(result["requests_imported"], 1)
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.content_type, "application/x-www-form-urlencoded")
        self.assertEqual(request.body["username"], "sample")
        points = {(point.location, point.name) for point in request.insertion_points}
        self.assertIn(("body", "username"), points)
        self.assertIn(("body", "password"), points)
        self.assertIn("state-changing-method", request.tags)
        self.assertIn("not-executed", request.tags)

    def test_swagger_file_formdata_selects_multipart_without_executing(self):
        spec = {
            "swagger": "2.0",
            "host": "example.com",
            "schemes": ["https"],
            "consumes": ["multipart/form-data"],
            "paths": {
                "/upload": {
                    "post": {
                        "parameters": [
                            {"name": "description", "in": "formData", "type": "string"},
                            {"name": "file", "in": "formData", "type": "file", "required": True},
                        ]
                    }
                }
            },
        }
        workspace = ResearchWorkspace("scan-swagger-upload", "https://example.com", "example.com")
        OpenAPIImporter("https://example.com").ingest(workspace, spec)
        request = next(iter(workspace.requests.values()))
        self.assertEqual(request.content_type, "multipart/form-data")
        self.assertEqual(request.body["file"], "[file-placeholder]")
        self.assertIn("not-executed", request.tags)
        self.assertIn("state-changing-method", request.tags)

    def test_swagger_body_parameter_uses_schema_fields_not_wrapper_name_for_json(self):
        spec = {
            "swagger": "2.0",
            "host": "example.com",
            "schemes": ["https"],
            "consumes": ["application/json"],
            "paths": {
                "/users": {
                    "post": {
                        "parameters": [
                            {
                                "name": "payload",
                                "in": "body",
                                "required": True,
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "enabled": {"type": "boolean"},
                                    },
                                },
                            }
                        ]
                    }
                }
            },
        }
        workspace = ResearchWorkspace("scan-swagger-json", "https://example.com", "example.com")
        OpenAPIImporter("https://example.com").ingest(workspace, spec)
        request = next(iter(workspace.requests.values()))
        points = {(point.location, point.name) for point in request.insertion_points}
        self.assertIn(("json", "name"), points)
        self.assertIn(("json", "enabled"), points)
        self.assertNotIn(("body", "payload"), points)


if __name__ == "__main__":
    unittest.main()
