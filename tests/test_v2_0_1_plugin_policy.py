import os
import unittest
from unittest.mock import patch

from dedsec.core.plugin_manager import PluginManager


class _EntryPoints:
    def select(self, **kwargs):
        raise AssertionError("entry-point enumeration reached")


class V201PluginPolicyTests(unittest.TestCase):
    def test_external_plugin_discovery_is_disabled_by_default(self):
        manager = PluginManager()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(PluginManager.ENABLE_ENV, None)
            with patch(
                "dedsec.core.plugin_manager.importlib_metadata.entry_points",
                side_effect=AssertionError("must not enumerate plugins"),
            ):
                self.assertEqual(manager.discover_entry_points(), 0)
        self.assertEqual(manager.get_registered_plugins(), {})
        self.assertEqual(manager.diagnostics(), [])

    def test_explicit_false_overrides_environment_opt_in(self):
        manager = PluginManager()
        with patch.dict(os.environ, {PluginManager.ENABLE_ENV: "1"}, clear=False):
            with patch(
                "dedsec.core.plugin_manager.importlib_metadata.entry_points",
                side_effect=AssertionError("explicit false must win"),
            ):
                self.assertEqual(manager.discover_entry_points(enabled=False), 0)
        self.assertEqual(manager.diagnostics(), [])

    def test_environment_opt_in_reaches_entry_point_enumeration(self):
        manager = PluginManager()
        with patch.dict(os.environ, {PluginManager.ENABLE_ENV: "true"}, clear=False):
            with patch(
                "dedsec.core.plugin_manager.importlib_metadata.entry_points",
                return_value=_EntryPoints(),
            ):
                self.assertEqual(manager.discover_entry_points(), 0)
        diagnostics = manager.diagnostics()
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0]["source"], "entry-points")
        self.assertIn("entry-point enumeration reached", diagnostics[0]["error"])

    def test_discovery_api_errors_are_diagnostic_not_silent(self):
        manager = PluginManager()
        with patch(
            "dedsec.core.plugin_manager.importlib_metadata.entry_points",
            side_effect=RuntimeError("metadata unavailable"),
        ):
            self.assertEqual(manager.discover_entry_points(enabled=True), 0)
        diagnostics = manager.diagnostics()
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0]["source"], "entry-points")
        self.assertIn("metadata unavailable", diagnostics[0]["error"])


if __name__ == "__main__":
    unittest.main()
