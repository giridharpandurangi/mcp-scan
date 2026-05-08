"""CLI tests using typer.testing.CliRunner.

Task 15.1 (optional) � Requirements 10.1�10.10

Tests cover:
- Each subcommand (static, dynamic, all, rules) with valid and invalid arguments
- Exit code 0: no HIGH+ findings
- Exit code 1: HIGH+ findings present
- Exit code 2: config error / runtime error / bad flag value
- --severity filter reduces output
- --rule flag runs only the specified rule
- --config flag loads configuration file
- --version prints version and exits 0
- --allow-destructive shows confirmation prompt; --yes skips it
- All four output formats (rich, json, sarif, markdown) produce valid output
- --output writes to file instead of stdout
"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from mcp_scan.cli import app
from mcp_scan.models import Finding, ScanConfig, ScanResult, Severity

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        rule_id="MCP001",
        severity=Severity.HIGH,
        target="src/server.py",
        location="src/server.py:10",
        message="Tainted URL passed to HTTP client",
        remediation="Validate the URL.",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _make_result(findings=None, scan_mode="static", target="src/") -> ScanResult:
    return ScanResult(
        findings=findings or [],
        scan_mode=scan_mode,
        target=target,
        timestamp=datetime.now(timezone.utc),
        tool_version="0.1.0",
    )


def _patch_scanner_static(result: ScanResult):
    """Context manager: patch Scanner.scan_static to return *result*."""
    return patch("mcp_scan.cli.Scanner.scan_static", return_value=result)


def _patch_scanner_dynamic(result: ScanResult):
    """Context manager: patch Scanner.scan_dynamic (async) to return *result*."""
    return patch("mcp_scan.cli.Scanner.scan_dynamic", new=AsyncMock(return_value=result))


def _patch_scanner_all(result: ScanResult):
    """Context manager: patch Scanner.scan_all (async) to return *result*."""
    return patch("mcp_scan.cli.Scanner.scan_all", new=AsyncMock(return_value=result))


# ---------------------------------------------------------------------------
# --version flag
# ---------------------------------------------------------------------------


class TestVersionFlag:
    def test_version_exits_0(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0

    def test_version_prints_version_string(self):
        result = runner.invoke(app, ["--version"])
        assert "mcp-bandit" in result.output

    def test_version_package_not_found_prints_0_0_0(self):
        import importlib.metadata
        with patch(
            "mcp_scan.cli.importlib.metadata.version",
            side_effect=importlib.metadata.PackageNotFoundError("mcp-scan"),
        ):
            result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "0.0.0" in result.output


# ---------------------------------------------------------------------------
# `rules` subcommand
# ---------------------------------------------------------------------------


class TestRulesSubcommand:
    def test_rules_exits_0(self):
        result = runner.invoke(app, ["rules"])
        assert result.exit_code == 0

    def test_rules_lists_known_rule_ids(self):
        result = runner.invoke(app, ["rules"])
        assert result.exit_code == 0
        # All 12 rules should appear
        for rule_id in ["MCP001", "MCP002", "MCP003", "MCP004", "MCP005",
                        "MCP010", "MCP011", "MCP012", "MCP013", "MCP014",
                        "MCP020", "MCP021"]:
            assert rule_id in result.output

    def test_rules_no_rules_registered(self):
        with patch("mcp_scan.cli.discover_rules", return_value=[]):
            result = runner.invoke(app, ["rules"])
        assert result.exit_code == 0
        assert "No rules registered" in result.output


# ---------------------------------------------------------------------------
# `static` subcommand � exit codes
# ---------------------------------------------------------------------------


class TestStaticExitCodes:
    def test_exit_0_when_no_high_findings(self, tmp_path):
        result_obj = _make_result(findings=[_make_finding(severity=Severity.LOW)])
        with _patch_scanner_static(result_obj):
            result = runner.invoke(app, ["static", "--path", str(tmp_path)])
        assert result.exit_code == 0

    def test_exit_1_when_high_finding(self, tmp_path):
        result_obj = _make_result(findings=[_make_finding(severity=Severity.HIGH)])
        with _patch_scanner_static(result_obj):
            result = runner.invoke(app, ["static", "--path", str(tmp_path)])
        assert result.exit_code == 1

    def test_exit_1_when_critical_finding(self, tmp_path):
        result_obj = _make_result(findings=[_make_finding(severity=Severity.CRITICAL)])
        with _patch_scanner_static(result_obj):
            result = runner.invoke(app, ["static", "--path", str(tmp_path)])
        assert result.exit_code == 1

    def test_exit_0_when_no_findings(self, tmp_path):
        result_obj = _make_result(findings=[])
        with _patch_scanner_static(result_obj):
            result = runner.invoke(app, ["static", "--path", str(tmp_path)])
        assert result.exit_code == 0

    def test_exit_2_on_scanner_exception(self, tmp_path):
        with patch("mcp_scan.cli.Scanner.scan_static", side_effect=RuntimeError("boom")):
            result = runner.invoke(app, ["static", "--path", str(tmp_path)])
        assert result.exit_code == 2

    def test_exit_2_on_invalid_format(self, tmp_path):
        result_obj = _make_result()
        with _patch_scanner_static(result_obj):
            result = runner.invoke(app, ["static", "--path", str(tmp_path), "--format", "xml"])
        assert result.exit_code == 2

    def test_exit_2_on_invalid_severity(self, tmp_path):
        result = runner.invoke(app, ["static", "--path", str(tmp_path), "--severity", "EXTREME"])
        assert result.exit_code == 2

    def test_exit_2_on_unknown_rule(self, tmp_path):
        result = runner.invoke(app, ["static", "--path", str(tmp_path), "--rule", "MCP999"])
        assert result.exit_code == 2

    def test_exit_2_on_missing_config_file(self, tmp_path):
        result = runner.invoke(
            app, ["static", "--path", str(tmp_path), "--config", str(tmp_path / "missing.toml")]
        )
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# `static` subcommand � output formats
# ---------------------------------------------------------------------------


class TestStaticOutputFormats:
    def test_format_rich_default(self, tmp_path):
        result_obj = _make_result(findings=[_make_finding()])
        with _patch_scanner_static(result_obj):
            result = runner.invoke(app, ["static", "--path", str(tmp_path)])
        assert result.exit_code == 1
        assert "MCP001" in result.output

    def test_format_json(self, tmp_path):
        result_obj = _make_result(findings=[_make_finding()])
        with _patch_scanner_static(result_obj):
            result = runner.invoke(app, ["static", "--path", str(tmp_path), "--format", "json"])
        assert result.exit_code == 1
        doc = json.loads(result.output)
        assert "findings" in doc
        assert doc["findings"][0]["rule_id"] == "MCP001"

    def test_format_sarif(self, tmp_path):
        result_obj = _make_result(findings=[_make_finding()])
        with _patch_scanner_static(result_obj):
            result = runner.invoke(app, ["static", "--path", str(tmp_path), "--format", "sarif"])
        assert result.exit_code == 1
        doc = json.loads(result.output)
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["results"][0]["ruleId"] == "MCP001"

    def test_format_markdown(self, tmp_path):
        result_obj = _make_result(findings=[_make_finding()])
        with _patch_scanner_static(result_obj):
            result = runner.invoke(app, ["static", "--path", str(tmp_path), "--format", "markdown"])
        assert result.exit_code == 1
        assert "# mcp-bandit Security Report" in result.output
        assert "MCP001" in result.output

    def test_format_json_zero_findings(self, tmp_path):
        result_obj = _make_result(findings=[])
        with _patch_scanner_static(result_obj):
            result = runner.invoke(app, ["static", "--path", str(tmp_path), "--format", "json"])
        assert result.exit_code == 0
        doc = json.loads(result.output)
        assert doc["findings"] == []

    def test_format_sarif_zero_findings(self, tmp_path):
        result_obj = _make_result(findings=[])
        with _patch_scanner_static(result_obj):
            result = runner.invoke(app, ["static", "--path", str(tmp_path), "--format", "sarif"])
        assert result.exit_code == 0
        doc = json.loads(result.output)
        assert doc["runs"][0]["results"] == []

    def test_format_markdown_zero_findings(self, tmp_path):
        result_obj = _make_result(findings=[])
        with _patch_scanner_static(result_obj):
            result = runner.invoke(app, ["static", "--path", str(tmp_path), "--format", "markdown"])
        assert result.exit_code == 0
        assert "No findings" in result.output


# ---------------------------------------------------------------------------
# `static` subcommand � --severity and --rule flags
# ---------------------------------------------------------------------------


class TestStaticFilters:
    def test_severity_filter_reduces_output(self, tmp_path):
        """--severity HIGH means LOW findings are excluded from the result."""
        # Use a real file so the scanner actually runs
        (tmp_path / "server.py").write_text(
            textwrap.dedent("""\
                import httpx

                @mcp.tool()
                def fetch(url):
                    return httpx.get(url)
            """)
        )
        result = runner.invoke(
            app, ["static", "--path", str(tmp_path), "--severity", "HIGH", "--format", "json"]
        )
        doc = json.loads(result.output)
        for finding in doc["findings"]:
            sev = Severity(finding["severity"])
            assert sev >= Severity.HIGH

    def test_rule_flag_runs_only_specified_rule(self, tmp_path):
        """--rule MCP001 suppresses all other rules."""
        (tmp_path / "server.py").write_text(
            textwrap.dedent("""\
                import httpx

                @mcp.tool()
                def fetch(url):
                    return httpx.get(url)
            """)
        )
        result = runner.invoke(
            app, ["static", "--path", str(tmp_path), "--rule", "MCP001", "--format", "json"]
        )
        doc = json.loads(result.output)
        rule_ids = {f["rule_id"] for f in doc["findings"]}
        # Only MCP001 (or no findings) � no other rule IDs
        assert rule_ids <= {"MCP001"}

    def test_severity_critical_only(self, tmp_path):
        """--severity CRITICAL: the config passed to Scanner has min_severity=CRITICAL."""
        captured_config = {}

        def capture_scan(self_scanner, path):
            captured_config["min_severity"] = self_scanner.config.min_severity
            return _make_result(findings=[])

        with patch("mcp_scan.cli.Scanner.scan_static", capture_scan):
            result = runner.invoke(
                app,
                ["static", "--path", str(tmp_path), "--severity", "CRITICAL", "--format", "json"],
            )
        assert result.exit_code == 0
        assert captured_config["min_severity"] == Severity.CRITICAL


# ---------------------------------------------------------------------------
# `static` subcommand � --output flag
# ---------------------------------------------------------------------------


class TestStaticOutputFile:
    def test_output_writes_to_file(self, tmp_path):
        out_file = tmp_path / "report.json"
        result_obj = _make_result(findings=[_make_finding()])
        with _patch_scanner_static(result_obj):
            result = runner.invoke(
                app,
                ["static", "--path", str(tmp_path), "--format", "json", "--output", str(out_file)],
            )
        assert result.exit_code == 1
        assert out_file.exists()
        doc = json.loads(out_file.read_text())
        assert "findings" in doc

    def test_output_nothing_to_stdout_when_file_given(self, tmp_path):
        out_file = tmp_path / "report.json"
        result_obj = _make_result(findings=[])
        with _patch_scanner_static(result_obj):
            result = runner.invoke(
                app,
                ["static", "--path", str(tmp_path), "--format", "json", "--output", str(out_file)],
            )
        # stdout should be empty (output went to file)
        assert result.output.strip() == ""

    def test_output_unwritable_path_exits_2(self, tmp_path):
        result_obj = _make_result(findings=[])
        with _patch_scanner_static(result_obj):
            result = runner.invoke(
                app,
                [
                    "static",
                    "--path", str(tmp_path),
                    "--format", "json",
                    "--output", str(tmp_path / "nonexistent_dir" / "report.json"),
                ],
            )
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# `dynamic` subcommand � exit codes
# ---------------------------------------------------------------------------


class TestDynamicExitCodes:
    def test_exit_0_when_no_high_findings(self):
        result_obj = _make_result(findings=[], scan_mode="dynamic")
        with _patch_scanner_dynamic(result_obj):
            result = runner.invoke(app, ["dynamic", "--target", "python server.py"])
        assert result.exit_code == 0

    def test_exit_1_when_high_finding(self):
        result_obj = _make_result(findings=[_make_finding()], scan_mode="dynamic")
        with _patch_scanner_dynamic(result_obj):
            result = runner.invoke(app, ["dynamic", "--target", "python server.py"])
        assert result.exit_code == 1

    def test_exit_2_on_scanner_exception(self):
        with patch("mcp_scan.cli.Scanner.scan_dynamic", new=AsyncMock(side_effect=RuntimeError("fail"))):
            result = runner.invoke(app, ["dynamic", "--target", "python server.py"])
        assert result.exit_code == 2

    def test_exit_2_on_invalid_format(self):
        result_obj = _make_result(scan_mode="dynamic")
        with _patch_scanner_dynamic(result_obj):
            result = runner.invoke(
                app, ["dynamic", "--target", "python server.py", "--format", "xml"]
            )
        assert result.exit_code == 2

    def test_missing_target_exits_nonzero(self):
        result = runner.invoke(app, ["dynamic"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# `dynamic` subcommand � output formats
# ---------------------------------------------------------------------------


class TestDynamicOutputFormats:
    def test_format_json(self):
        result_obj = _make_result(findings=[_make_finding()], scan_mode="dynamic")
        with _patch_scanner_dynamic(result_obj):
            result = runner.invoke(
                app, ["dynamic", "--target", "python server.py", "--format", "json"]
            )
        assert result.exit_code == 1
        doc = json.loads(result.output)
        assert doc["scan_mode"] == "dynamic"

    def test_format_sarif(self):
        result_obj = _make_result(findings=[_make_finding()], scan_mode="dynamic")
        with _patch_scanner_dynamic(result_obj):
            result = runner.invoke(
                app, ["dynamic", "--target", "python server.py", "--format", "sarif"]
            )
        assert result.exit_code == 1
        doc = json.loads(result.output)
        assert doc["version"] == "2.1.0"

    def test_format_markdown(self):
        result_obj = _make_result(findings=[_make_finding()], scan_mode="dynamic")
        with _patch_scanner_dynamic(result_obj):
            result = runner.invoke(
                app, ["dynamic", "--target", "python server.py", "--format", "markdown"]
            )
        assert result.exit_code == 1
        assert "# mcp-bandit Security Report" in result.output


# ---------------------------------------------------------------------------
# `dynamic` subcommand � --allow-destructive and --yes
# ---------------------------------------------------------------------------


class TestDynamicAllowDestructive:
    def test_allow_destructive_prompts_confirmation(self):
        """--allow-destructive without --yes shows a confirmation prompt."""
        result_obj = _make_result(scan_mode="dynamic")
        with _patch_scanner_dynamic(result_obj):
            # Simulate user typing "n" at the prompt
            result = runner.invoke(
                app,
                ["dynamic", "--target", "python server.py", "--allow-destructive"],
                input="n\n",
            )
        # User said no ? exit 0 (aborted, not an error)
        assert result.exit_code == 0

    def test_allow_destructive_yes_skips_prompt(self):
        """--allow-destructive --yes skips the confirmation prompt."""
        result_obj = _make_result(scan_mode="dynamic")
        with _patch_scanner_dynamic(result_obj):
            result = runner.invoke(
                app,
                ["dynamic", "--target", "python server.py", "--allow-destructive", "--yes"],
            )
        # No prompt, scan proceeds
        assert result.exit_code == 0

    def test_allow_destructive_confirmed_proceeds(self):
        """--allow-destructive with user confirming 'y' proceeds with scan."""
        result_obj = _make_result(scan_mode="dynamic")
        with _patch_scanner_dynamic(result_obj):
            result = runner.invoke(
                app,
                ["dynamic", "--target", "python server.py", "--allow-destructive"],
                input="y\n",
            )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# `all` subcommand � exit codes
# ---------------------------------------------------------------------------


class TestAllExitCodes:
    def test_exit_0_when_no_high_findings(self, tmp_path):
        result_obj = _make_result(findings=[], scan_mode="all")
        with _patch_scanner_all(result_obj):
            result = runner.invoke(
                app, ["all", "--path", str(tmp_path), "--target", "python server.py"]
            )
        assert result.exit_code == 0

    def test_exit_1_when_high_finding(self, tmp_path):
        result_obj = _make_result(findings=[_make_finding()], scan_mode="all")
        with _patch_scanner_all(result_obj):
            result = runner.invoke(
                app, ["all", "--path", str(tmp_path), "--target", "python server.py"]
            )
        assert result.exit_code == 1

    def test_exit_2_when_target_missing(self, tmp_path):
        result = runner.invoke(app, ["all", "--path", str(tmp_path)])
        assert result.exit_code == 2

    def test_exit_2_on_scanner_exception(self, tmp_path):
        with patch("mcp_scan.cli.Scanner.scan_all", new=AsyncMock(side_effect=RuntimeError("fail"))):
            result = runner.invoke(
                app, ["all", "--path", str(tmp_path), "--target", "python server.py"]
            )
        assert result.exit_code == 2

    def test_exit_2_on_invalid_format(self, tmp_path):
        result_obj = _make_result(scan_mode="all")
        with _patch_scanner_all(result_obj):
            result = runner.invoke(
                app,
                ["all", "--path", str(tmp_path), "--target", "python server.py", "--format", "xml"],
            )
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# `all` subcommand � output formats
# ---------------------------------------------------------------------------


class TestAllOutputFormats:
    def test_format_json(self, tmp_path):
        result_obj = _make_result(findings=[_make_finding()], scan_mode="all")
        with _patch_scanner_all(result_obj):
            result = runner.invoke(
                app,
                ["all", "--path", str(tmp_path), "--target", "python server.py", "--format", "json"],
            )
        assert result.exit_code == 1
        doc = json.loads(result.output)
        assert doc["scan_mode"] == "all"

    def test_format_sarif(self, tmp_path):
        result_obj = _make_result(findings=[_make_finding()], scan_mode="all")
        with _patch_scanner_all(result_obj):
            result = runner.invoke(
                app,
                ["all", "--path", str(tmp_path), "--target", "python server.py", "--format", "sarif"],
            )
        assert result.exit_code == 1
        doc = json.loads(result.output)
        assert doc["version"] == "2.1.0"

    def test_format_markdown(self, tmp_path):
        result_obj = _make_result(findings=[_make_finding()], scan_mode="all")
        with _patch_scanner_all(result_obj):
            result = runner.invoke(
                app,
                ["all", "--path", str(tmp_path), "--target", "python server.py", "--format", "markdown"],
            )
        assert result.exit_code == 1
        assert "# mcp-bandit Security Report" in result.output


# ---------------------------------------------------------------------------
# `all` subcommand � --allow-destructive
# ---------------------------------------------------------------------------


class TestAllAllowDestructive:
    def test_allow_destructive_prompts_confirmation(self, tmp_path):
        result_obj = _make_result(scan_mode="all")
        with _patch_scanner_all(result_obj):
            result = runner.invoke(
                app,
                ["all", "--path", str(tmp_path), "--target", "python server.py", "--allow-destructive"],
                input="n\n",
            )
        assert result.exit_code == 0

    def test_allow_destructive_yes_skips_prompt(self, tmp_path):
        result_obj = _make_result(scan_mode="all")
        with _patch_scanner_all(result_obj):
            result = runner.invoke(
                app,
                [
                    "all", "--path", str(tmp_path), "--target", "python server.py",
                    "--allow-destructive", "--yes",
                ],
            )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# --config flag
# ---------------------------------------------------------------------------


class TestConfigFlag:
    def test_config_toml_loaded(self, tmp_path):
        """--config loads a TOML file and applies its settings."""
        config_file = tmp_path / "mcp-scan.toml"
        config_file.write_text('[tool.mcp-scan]\ndisabled_rules = ["MCP002"]\n')

        mock_config = ScanConfig(disabled_rules=["MCP002"])
        result_obj = _make_result(findings=[])

        with patch("mcp_scan.cli.load_config", return_value=mock_config) as mock_load, \
             _patch_scanner_static(result_obj):
            result = runner.invoke(
                app, ["static", "--path", str(tmp_path), "--config", str(config_file)]
            )

        assert result.exit_code == 0
        mock_load.assert_called_once()

    def test_config_missing_file_exits_2(self, tmp_path):
        result = runner.invoke(
            app,
            ["static", "--path", str(tmp_path), "--config", str(tmp_path / "missing.toml")],
        )
        assert result.exit_code == 2

    def test_config_malformed_file_exits_2(self, tmp_path):
        config_file = tmp_path / "bad.toml"
        config_file.write_text("this is not valid toml ][")

        with patch("mcp_scan.cli.load_config", side_effect=ValueError("malformed")):
            result = runner.invoke(
                app, ["static", "--path", str(tmp_path), "--config", str(config_file)]
            )
        assert result.exit_code == 2

    def test_cli_severity_overrides_config(self, tmp_path):
        """CLI --severity takes precedence over config file min_severity."""
        config_file = tmp_path / "mcp-scan.toml"
        config_file.write_text("")

        # Config says INFO, CLI says HIGH � HIGH should win
        mock_config = ScanConfig(min_severity=Severity.INFO)
        captured_config = {}

        def capture_scan(self_scanner, path):
            captured_config["min_severity"] = self_scanner.config.min_severity
            return _make_result(findings=[])

        with patch("mcp_scan.cli.load_config", return_value=mock_config), \
             patch("mcp_scan.cli.Scanner.scan_static", capture_scan):
            result = runner.invoke(
                app,
                [
                    "static", "--path", str(tmp_path),
                    "--config", str(config_file),
                    "--severity", "HIGH",
                    "--format", "json",
                ],
            )

        assert result.exit_code == 0
        # CLI --severity HIGH should override config's INFO
        assert captured_config["min_severity"] == Severity.HIGH


# ---------------------------------------------------------------------------
# Invalid subcommand / flag
# ---------------------------------------------------------------------------


class TestInvalidInput:
    def test_invalid_subcommand_exits_nonzero(self):
        result = runner.invoke(app, ["nonexistent"])
        assert result.exit_code != 0

    def test_no_args_shows_help(self):
        result = runner.invoke(app, [])
        # no_args_is_help=True means help is shown and exit is 0
        assert "Usage" in result.output or result.exit_code == 0

    def test_static_invalid_flag_exits_nonzero(self, tmp_path):
        result = runner.invoke(app, ["static", "--nonexistent-flag"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# _get_formatter helper � all four formatters instantiated correctly
# ---------------------------------------------------------------------------


class TestGetFormatter:
    def test_rich_formatter_returned(self):
        from mcp_scan.cli import _get_formatter
        from mcp_scan.formatters import RichFormatter
        assert isinstance(_get_formatter("rich"), RichFormatter)

    def test_json_formatter_returned(self):
        from mcp_scan.cli import _get_formatter
        from mcp_scan.formatters import JsonFormatter
        assert isinstance(_get_formatter("json"), JsonFormatter)

    def test_sarif_formatter_returned(self):
        from mcp_scan.cli import _get_formatter
        from mcp_scan.formatters import SarifFormatter
        assert isinstance(_get_formatter("sarif"), SarifFormatter)

    def test_markdown_formatter_returned(self):
        from mcp_scan.cli import _get_formatter
        from mcp_scan.formatters import MarkdownFormatter
        assert isinstance(_get_formatter("markdown"), MarkdownFormatter)

    def test_invalid_format_raises_exit_2(self):
        import typer
        from mcp_scan.cli import _get_formatter
        with pytest.raises(typer.Exit) as exc_info:
            _get_formatter("xml")
        assert exc_info.value.exit_code == 2


# ---------------------------------------------------------------------------
# _parse_severity helper
# ---------------------------------------------------------------------------


class TestParseSeverity:
    def test_valid_severities_parsed(self):
        from mcp_scan.cli import _parse_severity
        for sev in Severity:
            assert _parse_severity(sev.value) == sev

    def test_case_insensitive(self):
        from mcp_scan.cli import _parse_severity
        assert _parse_severity("high") == Severity.HIGH
        assert _parse_severity("Critical") == Severity.CRITICAL

    def test_none_returns_none(self):
        from mcp_scan.cli import _parse_severity
        assert _parse_severity(None) is None

    def test_invalid_raises_exit_2(self):
        import typer
        from mcp_scan.cli import _parse_severity
        with pytest.raises(typer.Exit) as exc_info:
            _parse_severity("EXTREME")
        assert exc_info.value.exit_code == 2


# ---------------------------------------------------------------------------
# _build_config helper
# ---------------------------------------------------------------------------


class TestBuildConfig:
    def test_no_overrides_returns_default_config(self):
        from mcp_scan.cli import _build_config
        cfg = _build_config(None, None, None)
        assert cfg.min_severity == Severity.INFO
        assert cfg.disabled_rules == []

    def test_severity_override_applied(self):
        from mcp_scan.cli import _build_config
        cfg = _build_config(None, "HIGH", None)
        assert cfg.min_severity == Severity.HIGH

    def test_rule_override_disables_all_others(self):
        from mcp_scan.cli import _build_config
        cfg = _build_config(None, None, "MCP001")
        assert "MCP001" not in cfg.disabled_rules
        # All other rules should be disabled
        assert "MCP002" in cfg.disabled_rules

    def test_unknown_rule_raises_exit_2(self):
        import typer
        from mcp_scan.cli import _build_config
        with pytest.raises(typer.Exit) as exc_info:
            _build_config(None, None, "MCP999")
        assert exc_info.value.exit_code == 2


# ---------------------------------------------------------------------------
# _load_config_file � FileNotFoundError branch
# ---------------------------------------------------------------------------


class TestLoadConfigFileBranches:
    def test_file_not_found_error_exits_2(self, tmp_path):
        """load_config raising FileNotFoundError produces exit code 2."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("")  # file exists so CLI doesn't short-circuit

        with patch("mcp_scan.cli.load_config", side_effect=FileNotFoundError("not found")):
            result = runner.invoke(
                app, ["static", "--path", str(tmp_path), "--config", str(config_file)]
            )
        assert result.exit_code == 2
        assert "not found" in result.output or "config" in result.output.lower()
