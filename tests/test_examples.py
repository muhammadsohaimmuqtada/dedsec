import os
import unittest

from dedsec.core.auth import AuthProfile
from dedsec.core.scan_plan import ScanPlan
from dedsec.core.templates import TemplateDefinition


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class ExampleConfigurationTests(unittest.TestCase):
    def test_example_scan_plan_is_valid(self):
        plan = ScanPlan.load(os.path.join(ROOT, "examples", "scan-plan.example.yml"))
        self.assertEqual(plan.target, "https://example.com")
        self.assertTrue(plan.discovery.enabled)
        self.assertEqual(plan.traffic.maximum_impact, "active-safe")
        self.assertIn("./examples/templates", plan.templates.directories)

    def test_example_auth_profile_is_valid_placeholder_only(self):
        profile = AuthProfile.load(
            os.path.join(ROOT, "examples", "auth-profile.example.yml")
        )
        self.assertEqual(profile.kind, "bearer")
        self.assertEqual(profile.label, "researcher-customer")
        self.assertEqual(profile.token, "REPLACE_WITH_LOCAL_TEST_TOKEN")
        self.assertTrue(profile.verification)

    def test_example_template_is_valid_and_passive(self):
        definition = TemplateDefinition.load(
            os.path.join(ROOT, "examples", "templates", "server-header-observation.yml")
        )
        self.assertEqual(definition.template_id, "passive-server-header")
        self.assertEqual(definition.mode, "passive")
        self.assertEqual(definition.impact, "passive")


if __name__ == "__main__":
    unittest.main()
