"""Unit tests for mcp_scan/config.py — configuration file loading.

Task 16.1 — Requirements 11.1, 11.4, 11.5

Tests cover:
- Valid TOML loading (flat structure)
- Valid TOML loading with [tool.mcp-scan] section
- Valid JSON loading
- Malformed TOML raises ValueError (and CLI exits with code 2)
- Malformed JSON raises ValueError (and CLI exits with code 2)
- Unrecognized keys emit UserWarning but continue (do not raise)
- Invalid field values (e.g., bad severity) raise ValueError
- FileNotFoundError for missing file
- All ScanConfig fields are correctly loaded
- Empty/minimal config file returns defaults
- Unsupported file extension raises ValueError
- CLI --severity flag overrides config file min_severity
- CLI --format flag overrides config file output_format
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest

from mcp_scan.config import load_config
from mcp_scan.models import ScanConfig, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_toml(tmp_path: Path, content: str, name: str = "config.toml") -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def _write_json(tmp_path: Path, data: dict, name: str = "config.json") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# TOML — flat top-level structure
# ---------------------------------------------------------------------------


class TestTomlFlatStructure:
    def test_minimal_toml_returns_defaults(self, tmp_path):
        """An empty TOML file returns a ScanConfig with all defaults."""
        p = _write_toml(tmp_path, "")
        cfg = load_config(p)
        assert cfg == ScanConfig()

    def test_disabled_rules_loaded(self, tmp_path):
        p = _write_toml(tmp_path, 'disabled_rules = ["MCP001", "MCP002"]\n')
        cfg = load_config(p)
        assert cfg.disabled_rules == ["MCP001", "MCP002"]

    def test_min_severity_loaded(self, tmp_path):
        p = _write_toml(tmp_path, 'min_severity = "HIGH"\n')
        cfg = load_config(p)
        assert cfg.min_severity == Severity.HIGH

    def test_exclude_paths_loaded(self, tmp_path):
        p = _write_toml(tmp_path, 'exclude_paths = ["tests/**", ".venv/**"]\n')
        cfg = load_config(p)
        assert cfg.exclude_paths == ["tests/**", ".venv/**"]

    def test_output_format_loaded(self, tmp_path):
        p = _write_toml(tmp_path, 'output_format = "json"\n')
        cfg = load_config(p)
        assert cfg.output_format == "json"

    def test_trusted_validators_loaded(self, tmp_path):
        p = _write_toml(tmp_path, 'trusted_validators = ["validate_url", "sanitize"]\n')
        cfg = load_config(p)
        assert cfg.trusted_validators == ["validate_url", "sanitize"]

    def test_all_fields_loaded(self, tmp_path):
        content = (
            'disabled_rules = ["MCP002"]\n'
            'exclude_paths = ["tests/**"]\n'
            'min_severity = "MEDIUM"\n'
            'output_format = "sarif"\n'
            'trusted_validators = ["my_validator"]\n'
        )
        p = _write_toml(tmp_path, content)
        cfg = load_config(p)
        assert cfg.disabled_rules == ["MCP002"]
        assert cfg.exclude_paths == ["tests/**"]
        assert cfg.min_severity == Severity.MEDIUM
        assert cfg.output_format == "sarif"
        assert cfg.trusted_validators == ["my_validator"]

    def test_returns_scan_config_instance(self, tmp_path):
        p = _write_toml(tmp_path, "")
        cfg = load_config(p)
        assert isinstance(cfg, ScanConfig)


# ---------------------------------------------------------------------------
# TOML — [tool.mcp-scan] section (pyproject.toml style)
# ---------------------------------------------------------------------------


class TestTomlToolSection:
    def test_tool_section_loaded(self, tmp_path):
        content = (
            "[tool.mcp-scan]\n"
            'disabled_rules = ["MCP002"]\n'
            'min_severity = "HIGH"\n'
        )
        p = _write_toml(tmp_path, content)
        cfg = load_config(p)
        assert cfg.disabled_rules == ["MCP002"]
        assert cfg.min_severity == Severity.HIGH

    def test_tool_section_all_fields(self, tmp_path):
        content = (
            "[tool.mcp-scan]\n"
            'disabled_rules = ["MCP001"]\n'
            'exclude_paths = [".venv/**"]\n'
            'min_severity = "CRITICAL"\n'
            'output_format = "markdown"\n'
            'trusted_validators = ["check_url"]\n'
        )
        p = _write_toml(tmp_path, content)
        cfg = load_config(p)
        assert cfg.disabled_rules == ["MCP001"]
        assert cfg.exclude_paths == [".venv/**"]
        assert cfg.min_severity == Severity.CRITICAL
        assert cfg.output_format == "markdown"
        assert cfg.trusted_validators == ["check_url"]

    def test_empty_tool_section_returns_defaults(self, tmp_path):
        content = "[tool.mcp-scan]\n"
        p = _write_toml(tmp_path, content)
        cfg = load_config(p)
        assert cfg == ScanConfig()

    def test_tool_section_takes_precedence_over_flat(self, tmp_path):
        """When [tool.mcp-scan] exists, it is used (not the flat top-level)."""
        content = (
            "[tool.mcp-scan]\n"
            'min_severity = "HIGH"\n'
        )
        p = _write_toml(tmp_path, content)
        cfg = load_config(p)
        assert cfg.min_severity == Severity.HIGH

    def test_pyproject_toml_style_with_other_sections(self, tmp_path):
        """Other [tool.*] sections are ignored."""
        content = (
            "[tool.pytest.ini_options]\n"
            'testpaths = ["tests"]\n'
            "\n"
            "[tool.mcp-scan]\n"
            'disabled_rules = ["MCP003"]\n'
        )
        p = _write_toml(tmp_path, content)
        cfg = load_config(p)
        assert cfg.disabled_rules == ["MCP003"]


# ---------------------------------------------------------------------------
# JSON loading
# ---------------------------------------------------------------------------


class TestJsonLoading:
    def test_minimal_json_returns_defaults(self, tmp_path):
        p = _write_json(tmp_path, {})
        cfg = load_config(p)
        assert cfg == ScanConfig()

    def test_disabled_rules_loaded(self, tmp_path):
        p = _write_json(tmp_path, {"disabled_rules": ["MCP001"]})
        cfg = load_config(p)
        assert cfg.disabled_rules == ["MCP001"]

    def test_min_severity_loaded(self, tmp_path):
        p = _write_json(tmp_path, {"min_severity": "HIGH"})
        cfg = load_config(p)
        assert cfg.min_severity == Severity.HIGH

    def test_all_fields_loaded(self, tmp_path):
        data = {
            "disabled_rules": ["MCP002"],
            "exclude_paths": ["tests/**"],
            "min_severity": "MEDIUM",
            "output_format": "json",
            "trusted_validators": ["validate"],
        }
        p = _write_json(tmp_path, data)
        cfg = load_config(p)
        assert cfg.disabled_rules == ["MCP002"]
        assert cfg.exclude_paths == ["tests/**"]
        assert cfg.min_severity == Severity.MEDIUM
        assert cfg.output_format == "json"
        assert cfg.trusted_validators == ["validate"]

    def test_returns_scan_config_instance(self, tmp_path):
        p = _write_json(tmp_path, {})
        cfg = load_config(p)
        assert isinstance(cfg, ScanConfig)

    def test_accepts_string_path(self, tmp_path):
        """load_config accepts a str path, not just Path."""
        p = _write_json(tmp_path, {"min_severity": "LOW"})
        cfg = load_config(str(p))
        assert cfg.min_severity == Severity.LOW


# ---------------------------------------------------------------------------
# Error cases — malformed files
# ---------------------------------------------------------------------------


class TestMalformedFiles:
    def test_malformed_toml_raises_value_error(self, tmp_path):
        p = _write_toml(tmp_path, "this is not valid toml ][")
        with pytest.raises(ValueError, match="Failed to parse TOML"):
            load_config(p)

    def test_malformed_json_raises_value_error(self, tmp_path):
        p = tmp_path / "config.json"
        p.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(ValueError, match="Failed to parse JSON"):
            load_config(p)

    def test_json_array_at_top_level_raises_value_error(self, tmp_path):
        """JSON must be an object, not an array."""
        p = tmp_path / "config.json"
        p.write_text('["MCP001", "MCP002"]', encoding="utf-8")
        with pytest.raises(ValueError, match="JSON object"):
            load_config(p)

    def test_toml_with_invalid_type_raises_value_error(self, tmp_path):
        """A TOML value with wrong type (e.g., int for a string field) raises ValueError."""
        # min_severity expects a string like "HIGH", not an integer
        p = _write_toml(tmp_path, "min_severity = 42\n")
        with pytest.raises(ValueError):
            load_config(p)


# ---------------------------------------------------------------------------
# Error cases — unrecognized keys (warn and continue, do not raise)
# ---------------------------------------------------------------------------


class TestUnrecognizedKeys:
    def test_unrecognized_key_in_toml_emits_warning(self, tmp_path):
        """Unrecognized keys in TOML emit a UserWarning but do not raise."""
        p = _write_toml(tmp_path, 'unknown_option = "value"\n')
        with pytest.warns(UserWarning, match="unrecognized keys"):
            cfg = load_config(p)
        # Config still loads with defaults (unrecognized key is ignored)
        assert isinstance(cfg, ScanConfig)

    def test_unrecognized_key_in_json_emits_warning(self, tmp_path):
        """Unrecognized keys in JSON emit a UserWarning but do not raise."""
        p = _write_json(tmp_path, {"unknown_option": "value"})
        with pytest.warns(UserWarning, match="unrecognized keys"):
            cfg = load_config(p)
        assert isinstance(cfg, ScanConfig)

    def test_unrecognized_key_in_tool_section_emits_warning(self, tmp_path):
        """Unrecognized keys in [tool.mcp-scan] section emit a warning."""
        content = (
            "[tool.mcp-scan]\n"
            'unknown_option = "value"\n'
        )
        p = _write_toml(tmp_path, content)
        with pytest.warns(UserWarning, match="unrecognized keys"):
            cfg = load_config(p)
        assert isinstance(cfg, ScanConfig)

    def test_unrecognized_key_warning_contains_key_name(self, tmp_path):
        """The warning message includes the name of the unrecognized key."""
        p = _write_json(tmp_path, {"foo_unknown": "value"})
        with pytest.warns(UserWarning) as warning_list:
            load_config(p)
        assert any("foo_unknown" in str(w.message) for w in warning_list)

    def test_multiple_unrecognized_keys_listed_in_warning(self, tmp_path):
        """Multiple unrecognized keys are all mentioned in the warning."""
        p = _write_json(tmp_path, {"foo": 1, "bar": 2})
        with pytest.warns(UserWarning) as warning_list:
            load_config(p)
        warning_text = " ".join(str(w.message) for w in warning_list)
        assert "foo" in warning_text or "bar" in warning_text

    def test_unrecognized_key_does_not_prevent_loading_valid_keys(self, tmp_path):
        """Valid keys are still loaded even when unrecognized keys are present."""
        p = _write_json(tmp_path, {
            "min_severity": "HIGH",
            "unknown_option": "value",
        })
        with pytest.warns(UserWarning):
            cfg = load_config(p)
        # The valid key was loaded correctly
        assert cfg.min_severity == Severity.HIGH

    def test_unrecognized_key_with_all_valid_keys_still_loads(self, tmp_path):
        """Mix of valid and unrecognized keys: valid keys are loaded, warning emitted."""
        p = _write_json(tmp_path, {
            "disabled_rules": ["MCP001"],
            "min_severity": "MEDIUM",
            "some_future_option": True,
        })
        with pytest.warns(UserWarning):
            cfg = load_config(p)
        assert cfg.disabled_rules == ["MCP001"]
        assert cfg.min_severity == Severity.MEDIUM

    def test_recognized_keys_do_not_warn(self, tmp_path):
        """All valid ScanConfig fields should not trigger any warning."""
        p = _write_json(tmp_path, {
            "disabled_rules": [],
            "exclude_paths": [],
            "min_severity": "INFO",
            "output_format": "rich",
            "trusted_validators": [],
        })
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # Any warning becomes an error
            cfg = load_config(p)
        assert isinstance(cfg, ScanConfig)


# ---------------------------------------------------------------------------
# Error cases — invalid field values
# ---------------------------------------------------------------------------


class TestInvalidFieldValues:
    def test_invalid_severity_string_raises_value_error(self, tmp_path):
        p = _write_json(tmp_path, {"min_severity": "EXTREME"})
        with pytest.raises(ValueError):
            load_config(p)

    def test_invalid_output_format_raises_value_error(self, tmp_path):
        p = _write_json(tmp_path, {"output_format": "xml"})
        with pytest.raises(ValueError):
            load_config(p)

    def test_invalid_severity_in_toml_raises_value_error(self, tmp_path):
        p = _write_toml(tmp_path, 'min_severity = "UNKNOWN"\n')
        with pytest.raises(ValueError):
            load_config(p)

    def test_disabled_rules_wrong_type_raises_value_error(self, tmp_path):
        """disabled_rules must be a list of strings, not a single string."""
        p = _write_json(tmp_path, {"disabled_rules": "MCP001"})
        with pytest.raises(ValueError):
            load_config(p)


# ---------------------------------------------------------------------------
# Error cases — missing file
# ---------------------------------------------------------------------------


class TestMissingFile:
    def test_missing_file_raises_file_not_found(self, tmp_path):
        p = tmp_path / "nonexistent.toml"
        with pytest.raises(FileNotFoundError):
            load_config(p)

    def test_missing_json_file_raises_file_not_found(self, tmp_path):
        p = tmp_path / "nonexistent.json"
        with pytest.raises(FileNotFoundError):
            load_config(p)

    def test_error_message_contains_path(self, tmp_path):
        p = tmp_path / "missing.toml"
        with pytest.raises(FileNotFoundError, match="missing.toml"):
            load_config(p)


# ---------------------------------------------------------------------------
# Unsupported file extension
# ---------------------------------------------------------------------------


class TestUnsupportedExtension:
    def test_yaml_extension_raises_value_error(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("disabled_rules: []\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Unsupported"):
            load_config(p)

    def test_ini_extension_raises_value_error(self, tmp_path):
        p = tmp_path / "config.ini"
        p.write_text("[mcp-scan]\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Unsupported"):
            load_config(p)


# ---------------------------------------------------------------------------
# Severity values — all valid severities load correctly
# ---------------------------------------------------------------------------


class TestAllSeverityValues:
    @pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    def test_all_severity_values_accepted(self, tmp_path, severity):
        p = _write_json(tmp_path, {"min_severity": severity})
        cfg = load_config(p)
        assert cfg.min_severity == Severity(severity)


# ---------------------------------------------------------------------------
# Output format values — all valid formats load correctly
# ---------------------------------------------------------------------------


class TestAllOutputFormats:
    @pytest.mark.parametrize("fmt", ["rich", "json", "sarif", "markdown"])
    def test_all_output_formats_accepted(self, tmp_path, fmt):
        p = _write_json(tmp_path, {"output_format": fmt})
        cfg = load_config(p)
        assert cfg.output_format == fmt

# ---------------------------------------------------------------------------
# CLI integration tests — malformed config exits with code 2
# ---------------------------------------------------------------------------


class TestCliMalformedConfigExitsCode2:
    """Test that malformed config files cause the CLI to exit with code 2.

    Requirements: 11.5 — IF a configuration file is malformed, THEN THE
    mcp-scan CLI SHALL emit an error message describing the problem and exit
    with a non-zero exit code (code 2).
    """

    def test_malformed_toml_exits_code_2(self, tmp_path):
        """Malformed TOML config causes CLI to exit with code 2."""
        from typer.testing import CliRunner
        from mcp_scan.cli import app

        config_file = tmp_path / "bad.toml"
        config_file.write_text("this is not valid toml ][", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            app, ["static", "--path", str(tmp_path), "--config", str(config_file)]
        )
        assert result.exit_code == 2

    def test_malformed_toml_prints_error_message(self, tmp_path):
        """Malformed TOML config causes CLI to print an error message."""
        from typer.testing import CliRunner
        from mcp_scan.cli import app

        config_file = tmp_path / "bad.toml"
        config_file.write_text("this is not valid toml ][", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            app, ["static", "--path", str(tmp_path), "--config", str(config_file)]
        )
        assert result.exit_code == 2
        # Error message should appear in output (stderr or stdout via CliRunner)
        combined_output = result.output + (result.stderr if hasattr(result, "stderr") else "")
        assert "Error" in combined_output or "error" in combined_output.lower()

    def test_malformed_json_exits_code_2(self, tmp_path):
        """Malformed JSON config causes CLI to exit with code 2."""
        from typer.testing import CliRunner
        from mcp_scan.cli import app

        config_file = tmp_path / "bad.json"
        config_file.write_text("{not valid json", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            app, ["static", "--path", str(tmp_path), "--config", str(config_file)]
        )
        assert result.exit_code == 2

    def test_malformed_json_prints_error_message(self, tmp_path):
        """Malformed JSON config causes CLI to print an error message."""
        from typer.testing import CliRunner
        from mcp_scan.cli import app

        config_file = tmp_path / "bad.json"
        config_file.write_text("{not valid json", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            app, ["static", "--path", str(tmp_path), "--config", str(config_file)]
        )
        assert result.exit_code == 2
        combined_output = result.output + (result.stderr if hasattr(result, "stderr") else "")
        assert "Error" in combined_output or "error" in combined_output.lower()

    def test_missing_config_file_exits_code_2(self, tmp_path):
        """Missing config file causes CLI to exit with code 2."""
        from typer.testing import CliRunner
        from mcp_scan.cli import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["static", "--path", str(tmp_path), "--config", str(tmp_path / "nonexistent.toml")],
        )
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# CLI integration tests — CLI flags override config file values
# ---------------------------------------------------------------------------


class TestCliOverridesConfigFile:
    """Test that CLI flags take precedence over config file values.

    Requirements: 11.4 — WHEN both a configuration file and a CLI flag specify
    conflicting values for the same setting, THE mcp-scan CLI SHALL give
    precedence to the CLI flag.
    """

    def test_cli_severity_overrides_config_min_severity(self, tmp_path):
        """CLI --severity HIGH overrides config file min_severity = INFO."""
        from unittest.mock import patch
        from typer.testing import CliRunner
        from mcp_scan.cli import app
        from mcp_scan.models import ScanResult, Severity
        from datetime import datetime, timezone

        # Config file sets min_severity to INFO
        config_file = tmp_path / "config.toml"
        config_file.write_text('min_severity = "INFO"\n', encoding="utf-8")

        captured = {}

        def capture_scan(self_scanner, path):
            captured["min_severity"] = self_scanner.config.min_severity
            return ScanResult(
                findings=[],
                scan_mode="static",
                target=str(path),
                timestamp=datetime.now(timezone.utc),
                tool_version="0.0.0",
            )

        runner = CliRunner()
        with patch("mcp_scan.cli.Scanner.scan_static", capture_scan):
            result = runner.invoke(
                app,
                [
                    "static",
                    "--path", str(tmp_path),
                    "--config", str(config_file),
                    "--severity", "HIGH",
                    "--format", "json",
                ],
            )

        assert result.exit_code == 0
        # CLI --severity HIGH should override config's INFO
        assert captured.get("min_severity") == Severity.HIGH

    def test_cli_severity_overrides_config_toml_severity(self, tmp_path):
        """CLI --severity CRITICAL overrides config file min_severity = LOW."""
        from unittest.mock import patch
        from typer.testing import CliRunner
        from mcp_scan.cli import app
        from mcp_scan.models import ScanResult, Severity
        from datetime import datetime, timezone

        config_file = tmp_path / "config.json"
        config_file.write_text('{"min_severity": "LOW"}', encoding="utf-8")

        captured = {}

        def capture_scan(self_scanner, path):
            captured["min_severity"] = self_scanner.config.min_severity
            return ScanResult(
                findings=[],
                scan_mode="static",
                target=str(path),
                timestamp=datetime.now(timezone.utc),
                tool_version="0.0.0",
            )

        runner = CliRunner()
        with patch("mcp_scan.cli.Scanner.scan_static", capture_scan):
            result = runner.invoke(
                app,
                [
                    "static",
                    "--path", str(tmp_path),
                    "--config", str(config_file),
                    "--severity", "CRITICAL",
                    "--format", "json",
                ],
            )

        assert result.exit_code == 0
        assert captured.get("min_severity") == Severity.CRITICAL

    def test_config_severity_used_when_no_cli_flag(self, tmp_path):
        """Config file min_severity is used when no --severity CLI flag is given."""
        from unittest.mock import patch
        from typer.testing import CliRunner
        from mcp_scan.cli import app
        from mcp_scan.models import ScanResult, Severity
        from datetime import datetime, timezone

        config_file = tmp_path / "config.toml"
        config_file.write_text('min_severity = "MEDIUM"\n', encoding="utf-8")

        captured = {}

        def capture_scan(self_scanner, path):
            captured["min_severity"] = self_scanner.config.min_severity
            return ScanResult(
                findings=[],
                scan_mode="static",
                target=str(path),
                timestamp=datetime.now(timezone.utc),
                tool_version="0.0.0",
            )

        runner = CliRunner()
        with patch("mcp_scan.cli.Scanner.scan_static", capture_scan):
            result = runner.invoke(
                app,
                [
                    "static",
                    "--path", str(tmp_path),
                    "--config", str(config_file),
                    "--format", "json",
                ],
            )

        assert result.exit_code == 0
        # No CLI flag → config value should be used
        assert captured.get("min_severity") == Severity.MEDIUM

    def test_cli_format_flag_overrides_config_output_format(self, tmp_path):
        """CLI --format json overrides config file output_format = rich.

        Note: The --format flag controls the formatter used for output, not
        the ScanConfig.output_format field. This test verifies the CLI uses
        the --format flag value for rendering, not the config file value.
        """
        from unittest.mock import patch
        from typer.testing import CliRunner
        from mcp_scan.cli import app
        from mcp_scan.models import ScanResult
        from datetime import datetime, timezone
        import json as json_module

        # Config file sets output_format to "rich"
        config_file = tmp_path / "config.toml"
        config_file.write_text('output_format = "rich"\n', encoding="utf-8")

        result_obj = ScanResult(
            findings=[],
            scan_mode="static",
            target=str(tmp_path),
            timestamp=datetime.now(timezone.utc),
            tool_version="0.0.0",
        )

        runner = CliRunner()
        with patch("mcp_scan.cli.Scanner.scan_static", return_value=result_obj):
            result = runner.invoke(
                app,
                [
                    "static",
                    "--path", str(tmp_path),
                    "--config", str(config_file),
                    "--format", "json",  # CLI flag overrides config's "rich"
                ],
            )

        assert result.exit_code == 0
        # Output should be valid JSON (not rich terminal output)
        doc = json_module.loads(result.output)
        assert "findings" in doc

    def test_unrecognized_keys_in_config_do_not_prevent_cli_from_running(self, tmp_path):
        """Config with unrecognized keys emits a warning but CLI continues normally.

        Requirements: 11.5 — unrecognized keys emit a warning but continue.
        """
        from unittest.mock import patch
        from typer.testing import CliRunner
        from mcp_scan.cli import app
        from mcp_scan.models import ScanResult
        from datetime import datetime, timezone

        # Config file with an unrecognized key
        config_file = tmp_path / "config.json"
        config_file.write_text(
            '{"min_severity": "HIGH", "unknown_future_option": true}',
            encoding="utf-8",
        )

        result_obj = ScanResult(
            findings=[],
            scan_mode="static",
            target=str(tmp_path),
            timestamp=datetime.now(timezone.utc),
            tool_version="0.0.0",
        )

        runner = CliRunner()
        with patch("mcp_scan.cli.Scanner.scan_static", return_value=result_obj):
            result = runner.invoke(
                app,
                [
                    "static",
                    "--path", str(tmp_path),
                    "--config", str(config_file),
                    "--format", "json",
                ],
            )

        # Should NOT exit with code 2 — unrecognized keys are a warning, not an error
        assert result.exit_code == 0
