import unittest

from dedsec.core.crawler import CrawlConfig, CrawlerEngine, FormField, FormSurface, _SurfaceParser
from dedsec.core.scope import ScopePolicy
from dedsec.core.workspace import InsertionPoint, RequestRecord, ResearchWorkspace


class _Context:
    def __init__(self):
        self.target_url = "https://example.com/"
        self.domain = "example.com"
        self.timeout = 2
        self.scope = ScopePolicy.from_root("example.com")
        self._transport = object()

    def get_transport(self, *args, **kwargs):
        return self._transport


class V201RequestModelTests(unittest.TestCase):
    def test_explicit_points_augment_inference_instead_of_suppressing_it(self):
        request = RequestRecord.build(
            "POST",
            "https://example.com/users/1?view=full",
            body={"profile": {"name": "researcher", "enabled": True}},
            content_type="application/json",
            insertion_points=[
                InsertionPoint(
                    location="path",
                    name="id",
                    value=1,
                    value_type="integer",
                    required=True,
                    source="openapi",
                )
            ],
        )
        points = {(point.location, point.name) for point in request.insertion_points}
        self.assertIn(("path", "id"), points)
        self.assertIn(("query", "view"), points)
        self.assertIn(("json", "profile.name"), points)
        self.assertIn(("json", "profile.enabled"), points)

    def test_explicit_point_overrides_generic_inference_for_same_input(self):
        explicit = InsertionPoint(
            location="query",
            name="id",
            value="1",
            value_type="integer",
            required=True,
            source="openapi",
            metadata={"schema": True},
        )
        request = RequestRecord.build(
            "GET",
            "https://example.com/users?id=1",
            insertion_points=[explicit],
        )
        matches = [
            point for point in request.insertion_points
            if point.location == "query" and point.name == "id"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].source, "openapi")
        self.assertTrue(matches[0].required)

    def test_form_encoded_dict_is_not_mislabeled_as_json(self):
        request = RequestRecord.build(
            "POST",
            "https://example.com/login",
            body={"username": "researcher", "password": ""},
            content_type="application/x-www-form-urlencoded",
        )
        locations = {(point.location, point.name) for point in request.insertion_points}
        self.assertIn(("body", "username"), locations)
        self.assertIn(("body", "password"), locations)
        self.assertFalse(any(location == "json" for location, _ in locations))

    def test_multipart_structured_body_is_not_mislabeled_as_json(self):
        request = RequestRecord.build(
            "POST",
            "https://example.com/upload",
            body={"description": "sample", "file": "placeholder"},
            content_type="multipart/form-data",
        )
        locations = {(point.location, point.name) for point in request.insertion_points}
        self.assertEqual(locations, {("body", "description"), ("body", "file")})

    def test_crawler_records_multipart_form_without_fabricating_wire_body(self):
        context = _Context()
        workspace = ResearchWorkspace("scan-form", context.target_url, context.domain)
        crawler = CrawlerEngine(context, workspace, CrawlConfig(max_depth=1, max_pages=1))
        record = crawler._record_form(
            context.target_url,
            FormSurface(
                action="/upload",
                method="POST",
                enctype="multipart/form-data",
                fields=[
                    FormField("description", "text", "sample"),
                    FormField("file", "file", ""),
                ],
            ),
        )
        self.assertIsNotNone(record)
        self.assertEqual(record.method, "POST")
        self.assertEqual(record.body, {"description": "sample", "file": ""})
        self.assertFalse(record.metadata["wire_body_synthesized"])
        self.assertIn("not-submitted", record.tags)
        self.assertIn("state-changing-method", record.tags)

    def test_crawler_preserves_declared_nonstandard_form_method_as_surface(self):
        context = _Context()
        workspace = ResearchWorkspace("scan-method", context.target_url, context.domain)
        crawler = CrawlerEngine(context, workspace, CrawlConfig(max_depth=1, max_pages=1))
        record = crawler._record_form(
            context.target_url,
            FormSurface(
                action="/profile",
                method="PUT",
                fields=[FormField("display_name", "text", "researcher")],
            ),
        )
        self.assertEqual(record.method, "PUT")
        self.assertIn("state-changing-method", record.tags)
        self.assertIn("not-submitted", record.tags)

    def test_surface_parser_preserves_unclosed_form(self):
        parser = _SurfaceParser()
        parser.feed("<form action='/login' method='post'><input name='username'>")
        parser.close()
        self.assertEqual(len(parser.forms), 1)
        self.assertEqual(parser.forms[0].action, "/login")
        self.assertEqual(parser.forms[0].fields[0].name, "username")

    def test_crawler_rejects_invalid_limits(self):
        with self.assertRaisesRegex(ValueError, "max_links_per_page"):
            CrawlerEngine(_Context(), ResearchWorkspace("scan-x", "https://example.com", "example.com"), CrawlConfig(max_links_per_page=0))


if __name__ == "__main__":
    unittest.main()
