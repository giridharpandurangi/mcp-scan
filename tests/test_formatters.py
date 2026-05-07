"""Snapshot tests for all output formatters.

Each formatter is rendered against a fixed, deterministic ScanResult and
compared against a stored reference file in tests/snapshots/.

Requirements: 9.1, 9.2, 9.3, 9.4, 9.6, 13.5
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mcp_scan.formatters.json_formatter import JsonFormatter
from mcp_scan.formatters.markdown_formatter import MarkdownFormatter
from mcp_scan.formatters.rich_formatter import RichFormatter
from mcp_scan.formatters.sarif_formatter import SarifFormatter
from mcp_scan.models import Finding, ScanResult, Severity

SNAPSHOTS = Path(__file__).parent / "snapshots"

# ---------------------------------------------------------------------------
# Fixed deterministic ScanResult fixtures
# ---------------------------------------------------------------------------

FIXED_TIMESTAMP = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def result_with_findings() -> ScanResult:
    """A fixed ScanResult with three findings of varying severity."""
    return ScanResult(
        findings=[
            Finding(
                rule_id="MCP001",
                severity=Severity.HIGH,
                target="src/server.py",
                location="src/server.py:42",
                message="Tainted URL passed to HTTP client — potential SSRF. Sink: httpx.get",
                remediation="Validate the URL against an allowlist before passing it to an HTTP client.",
            ),
            Finding(
                rule_id="MCP010",
                severity=Severity.CRITICAL,
                target="src/server.py",
                location="src/server.py:10",
                message="Hardcoded API key assigned to variable api_key.",
                remediation="Use environment variables or a secrets manager instead of hardcoding credentials.",
            ),
            Finding(
                rule_id="MCP021",
                severity=Severity.HIGH,
                target="src/server.py",
                location="src/server.py:5",
                message="Tool description contains prompt injection phrase: ignore previous instructions",
                remediation="Remove or rewrite the tool description to avoid injection phrases.",
            ),
        ],
        scan_mode="static",
        target="src/server.py",
        timestamp=FIXED_TIMESTAMP,
        tool_version="0.1.0",
    )


@pytest.fixture
def result_zero_findings() -> ScanResult:
    """A fixed ScanResult with no findings."""
    return ScanResult(
        findings=[],
        scan_mode="static",
        target="src/clean.py",
        timestamp=FIXED_TIMESTAMP,
        tool_version="0.1.0",
    )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _read_snapshot(name: str) -> str:
    """Read a snapshot file and return its contents."""
    return (SNAPSHOTS / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# JsonFormatter snapshot tests
# ---------------------------------------------------------------------------


class TestJsonFormatter:
    def test_with_findings_matches_snapshot(self, result_with_findings: ScanResult) -> None:
        """JSON output with findings matches stored snapshot."""
        formatter = JsonFormatter()
        output = formatter.format(result_with_findings)
        expected = _read_snapshot("json_with_findings.json")
        assert output == expected

    def test_zero_findings_matches_snapshot(self, result_zero_findings: ScanResult) -> None:
        """JSON output with zero findings matches stored snapshot."""
        formatter = JsonFormatter()
        output = formatter.format(result_zero_findings)
        expected = _read_snapshot("json_zero_findings.json")
        assert output == expected

    def test_output_is_valid_json(self, result_with_findings: ScanResult) -> None:
        """JSON formatter output is valid JSON."""
        formatter = JsonFormatter()
        output = formatter.format(result_with_findings)
        parsed = json.loads(output)
        assert "findings" in parsed
        assert len(parsed["findings"]) == 3

    def test_zero_findings_is_valid_json(self, result_zero_findings: ScanResult) -> None:
        """JSON formatter zero-findings output is valid JSON with empty findings list."""
        formatter = JsonFormatter()
        output = formatter.format(result_zero_findings)
        parsed = json.loads(output)
        assert parsed["findings"] == []

    def test_round_trip(self, result_with_findings: ScanResult) -> None:
        """JSON formatter output round-trips back to an equivalent ScanResult."""
        formatter = JsonFormatter()
        output = formatter.format(result_with_findings)
        restored = ScanResult.model_validate_json(output)
        assert restored == result_with_findings


# ---------------------------------------------------------------------------
# SarifFormatter snapshot tests
# ---------------------------------------------------------------------------


class TestSarifFormatter:
    def test_with_findings_matches_snapshot(self, result_with_findings: ScanResult) -> None:
        """SARIF output with findings matches stored snapshot."""
        formatter = SarifFormatter()
        output = formatter.format(result_with_findings)
        expected = _read_snapshot("sarif_with_findings.json")
        assert output == expected

    def test_zero_findings_matches_snapshot(self, result_zero_findings: ScanResult) -> None:
        """SARIF output with zero findings matches stored snapshot."""
        formatter = SarifFormatter()
        output = formatter.format(result_zero_findings)
        expected = _read_snapshot("sarif_zero_findings.json")
        assert output == expected

    def test_output_is_valid_sarif(self, result_with_findings: ScanResult) -> None:
        """SARIF formatter output is valid JSON with SARIF 2.1.0 structure."""
        formatter = SarifFormatter()
        output = formatter.format(result_with_findings)
        doc = json.loads(output)
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc
        assert len(doc["runs"]) == 1
        run = doc["runs"][0]
        assert "tool" in run
        assert "results" in run

    def test_severity_level_mapping(self, result_with_findings: ScanResult) -> None:
        """SARIF severity levels are correctly mapped from Finding severity."""
        formatter = SarifFormatter()
        output = formatter.format(result_with_findings)
        doc = json.loads(output)
        results = doc["runs"][0]["results"]
        # MCP001 is HIGH → error
        mcp001 = next(r for r in results if r["ruleId"] == "MCP001")
        assert mcp001["level"] == "error"
        # MCP010 is CRITICAL → error
        mcp010 = next(r for r in results if r["ruleId"] == "MCP010")
        assert mcp010["level"] == "error"

    def test_severity_medium_maps_to_warning(self) -> None:
        """SARIF formatter maps MEDIUM severity to 'warning'."""
        result = ScanResult(
            findings=[
                Finding(
                    rule_id="MCP012",
                    severity=Severity.MEDIUM,
                    target="src/server.py",
                    location="src/server.py:20",
                    message="Insecure HTTP URL in auth context.",
                    remediation="Use HTTPS instead of HTTP.",
                )
            ],
            scan_mode="static",
            target="src/server.py",
            timestamp=FIXED_TIMESTAMP,
            tool_version="0.1.0",
        )
        formatter = SarifFormatter()
        doc = json.loads(formatter.format(result))
        assert doc["runs"][0]["results"][0]["level"] == "warning"

    def test_severity_low_maps_to_note(self) -> None:
        """SARIF formatter maps LOW severity to 'note'."""
        result = ScanResult(
            findings=[
                Finding(
                    rule_id="MCP002",
                    severity=Severity.LOW,
                    target="src/server.py",
                    location="src/server.py:30",
                    message="HTTP client call missing timeout.",
                    remediation="Add a timeout argument.",
                )
            ],
            scan_mode="static",
            target="src/server.py",
            timestamp=FIXED_TIMESTAMP,
            tool_version="0.1.0",
        )
        formatter = SarifFormatter()
        doc = json.loads(formatter.format(result))
        assert doc["runs"][0]["results"][0]["level"] == "note"

    def test_zero_findings_has_empty_results(self, result_zero_findings: ScanResult) -> None:
        """SARIF formatter zero-findings output has empty results array."""
        formatter = SarifFormatter()
        doc = json.loads(formatter.format(result_zero_findings))
        assert doc["runs"][0]["results"] == []
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []

    def test_location_parsed_correctly(self, result_with_findings: ScanResult) -> None:
        """SARIF formatter correctly parses location strings into URI and line number."""
        formatter = SarifFormatter()
        doc = json.loads(formatter.format(result_with_findings))
        results = doc["runs"][0]["results"]
        mcp001 = next(r for r in results if r["ruleId"] == "MCP001")
        loc = mcp001["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/server.py"
        assert loc["region"]["startLine"] == 42

    def test_tool_version_in_driver(self, result_with_findings: ScanResult) -> None:
        """SARIF formatter includes tool version in driver metadata."""
        formatter = SarifFormatter()
        doc = json.loads(formatter.format(result_with_findings))
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver["name"] == "mcp-scan"
        assert driver["version"] == "0.1.0"


# ---------------------------------------------------------------------------
# MarkdownFormatter snapshot tests
# ---------------------------------------------------------------------------


class TestMarkdownFormatter:
    def test_with_findings_matches_snapshot(self, result_with_findings: ScanResult) -> None:
        """Markdown output with findings matches stored snapshot."""
        formatter = MarkdownFormatter()
        output = formatter.format(result_with_findings)
        expected = _read_snapshot("markdown_with_findings.md")
        assert output == expected

    def test_zero_findings_matches_snapshot(self, result_zero_findings: ScanResult) -> None:
        """Markdown output with zero findings matches stored snapshot."""
        formatter = MarkdownFormatter()
        output = formatter.format(result_zero_findings)
        expected = _read_snapshot("markdown_zero_findings.md")
        assert output == expected

    def test_with_findings_contains_summary_table(self, result_with_findings: ScanResult) -> None:
        """Markdown output with findings contains a summary table."""
        formatter = MarkdownFormatter()
        output = formatter.format(result_with_findings)
        assert "| Rule ID |" in output
        assert "| Severity |" in output
        assert "MCP001" in output
        assert "MCP010" in output
        assert "MCP021" in output

    def test_with_findings_contains_per_finding_sections(self, result_with_findings: ScanResult) -> None:
        """Markdown output with findings contains ### sections for each finding."""
        formatter = MarkdownFormatter()
        output = formatter.format(result_with_findings)
        assert "### 1." in output
        assert "### 2." in output
        assert "### 3." in output

    def test_zero_findings_success_message(self, result_zero_findings: ScanResult) -> None:
        """Markdown output with zero findings contains a success message."""
        formatter = MarkdownFormatter()
        output = formatter.format(result_zero_findings)
        assert "No findings" in output
        assert "successfully" in output

    def test_severity_values_present(self, result_with_findings: ScanResult) -> None:
        """Markdown output includes severity values for each finding."""
        formatter = MarkdownFormatter()
        output = formatter.format(result_with_findings)
        assert "HIGH" in output
        assert "CRITICAL" in output

    def test_remediation_present(self, result_with_findings: ScanResult) -> None:
        """Markdown output includes remediation guidance for each finding."""
        formatter = MarkdownFormatter()
        output = formatter.format(result_with_findings)
        assert "Remediation" in output


# ---------------------------------------------------------------------------
# RichFormatter snapshot tests
# ---------------------------------------------------------------------------


class TestRichFormatter:
    def test_with_findings_matches_snapshot(self, result_with_findings: ScanResult) -> None:
        """Rich output with findings matches stored snapshot."""
        formatter = RichFormatter()
        output = formatter.format(result_with_findings)
        expected = _read_snapshot("rich_with_findings.txt")
        assert output == expected

    def test_zero_findings_matches_snapshot(self, result_zero_findings: ScanResult) -> None:
        """Rich output with zero findings matches stored snapshot."""
        formatter = RichFormatter()
        output = formatter.format(result_zero_findings)
        expected = _read_snapshot("rich_zero_findings.txt")
        assert output == expected

    def test_with_findings_contains_rule_ids(self, result_with_findings: ScanResult) -> None:
        """Rich output with findings contains rule IDs."""
        formatter = RichFormatter()
        output = formatter.format(result_with_findings)
        assert "MCP001" in output
        assert "MCP010" in output
        assert "MCP021" in output

    def test_with_findings_contains_severity_values(self, result_with_findings: ScanResult) -> None:
        """Rich output with findings contains severity values."""
        formatter = RichFormatter()
        output = formatter.format(result_with_findings)
        assert "HIGH" in output
        assert "CRITICAL" in output

    def test_zero_findings_success_message(self, result_zero_findings: ScanResult) -> None:
        """Rich output with zero findings contains a success message."""
        formatter = RichFormatter()
        output = formatter.format(result_zero_findings)
        assert "No findings" in output

    def test_returns_string(self, result_with_findings: ScanResult) -> None:
        """Rich formatter returns a string."""
        formatter = RichFormatter()
        output = formatter.format(result_with_findings)
        assert isinstance(output, str)
        assert len(output) > 0

    def test_with_findings_contains_location(self, result_with_findings: ScanResult) -> None:
        """Rich output with findings contains location strings."""
        formatter = RichFormatter()
        output = formatter.format(result_with_findings)
        assert "src/server.py:42" in output
        assert "src/server.py:10" in output


# ---------------------------------------------------------------------------
# Formatter protocol compliance
# ---------------------------------------------------------------------------


class TestFormatterProtocol:
    """Verify all formatters implement the Formatter protocol."""

    @pytest.mark.parametrize(
        "formatter_cls",
        [JsonFormatter, SarifFormatter, MarkdownFormatter, RichFormatter],
    )
    def test_has_format_method(self, formatter_cls) -> None:
        """Each formatter class has a format(result) method."""
        formatter = formatter_cls()
        assert callable(getattr(formatter, "format", None))

    @pytest.mark.parametrize(
        "formatter_cls",
        [JsonFormatter, SarifFormatter, MarkdownFormatter, RichFormatter],
    )
    def test_format_returns_string(
        self, formatter_cls, result_with_findings: ScanResult
    ) -> None:
        """Each formatter's format() method returns a string."""
        formatter = formatter_cls()
        result = formatter.format(result_with_findings)
        assert isinstance(result, str)

    @pytest.mark.parametrize(
        "formatter_cls",
        [JsonFormatter, SarifFormatter, MarkdownFormatter, RichFormatter],
    )
    def test_zero_findings_returns_string(
        self, formatter_cls, result_zero_findings: ScanResult
    ) -> None:
        """Each formatter handles zero findings and returns a non-empty string."""
        formatter = formatter_cls()
        result = formatter.format(result_zero_findings)
        assert isinstance(result, str)
        assert len(result) > 0
