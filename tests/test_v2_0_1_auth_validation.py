import os
import tempfile
import unittest

from dedsec.core.auth import AuthProfile


class V201AuthValidationTests(unittest.TestCase):
    def _load(self, text):
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        path = os.path.join(tmpdir.name, "auth.yml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return AuthProfile.load(path)

    def test_unknown_auth_key_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unknown authentication-profile key"):
            self._load("kind: bearer\ntokn: secret\n")

    def test_invalid_verification_regex_is_rejected_at_load_time(self):
        with self.assertRaisesRegex(ValueError, "Invalid verification.body_regex regex"):
            self._load(
                "kind: bearer\n"
                "token: secret\n"
                "verification:\n"
                "  url: /me\n"
                "  body_regex: '('\n"
            )

    def test_get_workflow_body_is_rejected_before_execution(self):
        with self.assertRaisesRegex(ValueError, "cannot declare form or json"):
            self._load(
                "kind: workflow\n"
                "workflow:\n"
                "  - method: GET\n"
                "    url: /login\n"
                "    form:\n"
                "      user: researcher\n"
            )

    def test_capture_group_must_exist(self):
        with self.assertRaisesRegex(ValueError, "outside the regex group range"):
            self._load(
                "kind: workflow\n"
                "workflow:\n"
                "  - method: GET\n"
                "    url: /token\n"
                "    capture:\n"
                "      csrf:\n"
                "        regex: 'token=([a-z]+)'\n"
                "        group: 2\n"
            )

    def test_invalid_status_is_rejected_at_load_time(self):
        with self.assertRaisesRegex(ValueError, "invalid HTTP status"):
            self._load(
                "kind: bearer\n"
                "token: secret\n"
                "verification:\n"
                "  expect_status: 999\n"
            )

    def test_valid_workflow_profile_still_loads(self):
        profile = self._load(
            "label: researcher\n"
            "kind: workflow\n"
            "workflow:\n"
            "  - method: POST\n"
            "    url: /login\n"
            "    form:\n"
            "      username: researcher\n"
            "      password: secret\n"
            "    expect_status: [200, 302]\n"
            "verification:\n"
            "  url: /me\n"
            "  expect_status: 200\n"
            "  body_regex: 'researcher'\n"
        )
        self.assertEqual(profile.kind, "workflow")
        self.assertEqual(len(profile.workflow), 1)


if __name__ == "__main__":
    unittest.main()
