import unittest
from unittest.mock import patch

from dedsec import cli


class CliTests(unittest.TestCase):
    @patch("dedsec.cli.typer.run")
    @patch("dedsec.cli.typer.echo")
    def test_main_version_flag_exits_without_running_scan(self, mock_echo, mock_run):
        with patch.object(cli.sys, "argv", ["dedsec", "--version"]):
            cli.main()

        mock_echo.assert_called_once_with(f"DEDSEC v{cli.__version__}")
        mock_run.assert_not_called()

    @patch("dedsec.cli.typer.run")
    def test_main_runs_typer_for_regular_invocations(self, mock_run):
        with patch.object(cli.sys, "argv", ["dedsec", "https://example.com"]):
            cli.main()

        mock_run.assert_called_once_with(cli.scan)


if __name__ == "__main__":
    unittest.main()
