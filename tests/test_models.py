"""Unit tests for mcp_scan data models.

Tests cover:
- Severity enum values and ordering
- Finding field validation and defaults
- ScanResult serialization/deserialization round-trip with fixed examples
- ScanConfig defaults, validation, and round-trip
- RuleMetadata dataclass construction
"""

import pytest
from pydantic import ValidationError

from mcp_scan.models import Finding, RuleMetadata, ScanConfig, ScanResult, Severity


# ---------------------------------------------------------------------------
# Severity enum tests
# ---------------------------------------------------------------------------


class TestSeverityEnum:
    def test_all_values_present(self):
        values = {s.value for s in Severity}
        assert values == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_severity_is_str_enum(self):
        # Severity inherits from str so it can be used directly as a string
        assert isinstance(Severity.HIGH, str)
        assert Severity.HIGH == "HIGH"

    def test_severity_from_string(self):
        assert Severity("CRITICAL") is Severity.CRITICAL
        assert Severity("INFO") is Severity.INFO

    def test_invalid_severity_raises(self):
        with pytest.raises(ValueError):
            Severity("UNKNOWN")

    # --- Real ordering via .level / comparison operators ---

    def test_level_ranks_are_strictly_increasing(self):
        """INFO < LOW < MEDIUM < HIGH < CRITICAL by numeric level."""
        assert Severity.INFO.level < Severity.LOW.level
        assert Severity.LOW.level < Severity.MEDIUM.level
        assert Severity.MEDIUM.level < Severity.HIGH.level
        assert Severity.HIGH.level < Severity.CRITICAL.level

    def test_comparison_operators(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.HIGH
        assert Severity.HIGH <= Severity.CRITICAL
        assert Severity.CRITICAL >= Severity.CRITICAL

    def test_severity_usable_as_filter_threshold(self):
        """Simulate the filter pattern used in Scanner: severity >= min_severity."""
        findings_severities = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        threshold = Severity.HIGH
        above = [s for s in findings_severities if s >= threshold]
        assert above == [Severity.HIGH, Severity.CRITICAL]

    def test_severity_sorted(self):
        shuffled = [Severity.HIGH, Severity.INFO, Severity.CRITICAL, Severity.LOW, Severity.MEDIUM]
        result = sorted(shuffled, key=lambda s: s.level)
        assert result == [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


# ---------------------------------------------------------------------------
# Finding model tests
# ---------------------------------------------------------------------------


class TestFinding:
    def test_basic_construction(self, make_finding):
        f = make_finding()
        assert f.rule_id == "MCP001"
        assert f.severity == Severity.HIGH
        assert f.target == "src/server.py"
        assert f.location == "src/server.py:42"

    def test_confidence_default_is_high(self, make_finding):
        f = make_finding()
        assert f.confidence == "HIGH"

    def test_confidence_can_be_low(self, make_finding):
        f = make_finding(confidence="LOW")
        assert f.confidence == "LOW"

    def test_invalid_confidence_raises(self, make_finding):
        with pytest.raises(ValidationError):
            make_finding(confidence="MEDIUM")

    def test_severity_accepts_enum_value(self, make_finding):
        f = make_finding(severity=Severity.CRITICAL)
        assert f.severity == Severity.CRITICAL

    def test_severity_accepts_string(self, make_finding):
        f = make_finding(severity="MEDIUM")
        assert f.severity == Severity.MEDIUM

    def test_invalid_severity_raises(self, make_finding):
        with pytest.raises(ValidationError):
            make_finding(severity="EXTREME")

    def test_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            Finding(
                rule_id="MCP001",
                severity=Severity.HIGH,
                # target is missing
                location="src/server.py:42",
                message="msg",
                remediation="fix",
            )

    def test_json_round_trip(self, make_finding):
        f = make_finding()
        restored = Finding.model_validate_json(f.model_dump_json())
        assert restored == f


# ---------------------------------------------------------------------------
# ScanResult model tests
# ---------------------------------------------------------------------------


class TestScanResult:
    def _make_result(self, **overrides) -> ScanResult:
        defaults = dict(
            findings=[],
            scan_mode="static",
            target="src/",
            timestamp="2024-01-01T00:00:00Z",
            tool_version="0.1.0",
        )
        defaults.update(overrides)
        return ScanResult(**defaults)

    def test_basic_construction_empty_findings(self):
        r = self._make_result()
        assert r.findings == []
        assert r.scan_mode == "static"

    def test_with_findings(self, make_finding):
        finding = make_finding(rule_id="MCP010", severity=Severity.CRITICAL, message="Hardcoded API key")
        r = self._make_result(findings=[finding])
        assert len(r.findings) == 1
        assert r.findings[0].rule_id == "MCP010"

    def test_json_round_trip_empty(self):
        r = self._make_result()
        restored = ScanResult.model_validate_json(r.model_dump_json())
        assert restored == r

    def test_json_round_trip_with_findings(self, make_finding):
        finding = make_finding(confidence="LOW")
        r = self._make_result(findings=[finding], scan_mode="dynamic")
        restored = ScanResult.model_validate_json(r.model_dump_json())
        assert restored == r
        assert restored.findings[0].confidence == "LOW"

    def test_scan_mode_values(self):
        for mode in ("static", "dynamic", "all"):
            r = self._make_result(scan_mode=mode)
            assert r.scan_mode == mode

    def test_invalid_scan_mode_raises(self):
        with pytest.raises(ValidationError):
            self._make_result(scan_mode="unknown")

    def test_timestamp_accepts_iso_string(self):
        r = self._make_result(timestamp="2024-06-15T12:30:00+00:00")
        assert r.timestamp is not None

    def test_timestamp_rejects_garbage(self):
        with pytest.raises((ValidationError, ValueError)):
            self._make_result(timestamp="not-a-date")

    def test_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            ScanResult(
                findings=[],
                scan_mode="static",
                # target missing
                timestamp="2024-01-01T00:00:00Z",
                tool_version="0.1.0",
            )


# ---------------------------------------------------------------------------
# ScanConfig model tests
# ---------------------------------------------------------------------------


class TestScanConfig:
    def test_defaults(self):
        cfg = ScanConfig()
        assert cfg.disabled_rules == []
        assert cfg.exclude_paths == []
        assert cfg.min_severity == Severity.INFO
        assert cfg.output_format == "rich"
        assert cfg.trusted_validators == []

    def test_custom_values(self):
        cfg = ScanConfig(
            disabled_rules=["MCP002"],
            exclude_paths=["tests/**"],
            min_severity=Severity.HIGH,
            output_format="json",
            trusted_validators=["validate_url"],
        )
        assert cfg.disabled_rules == ["MCP002"]
        assert cfg.min_severity == Severity.HIGH

    def test_invalid_output_format_raises(self):
        with pytest.raises(ValidationError):
            ScanConfig(output_format="xml")

    def test_json_round_trip(self):
        cfg = ScanConfig(
            disabled_rules=["MCP002", "MCP003"],
            exclude_paths=["tests/**", "vendor/**"],
            min_severity=Severity.MEDIUM,
            output_format="sarif",
            trusted_validators=["validate_url", "is_safe_path"],
        )
        restored = ScanConfig.model_validate_json(cfg.model_dump_json())
        assert restored == cfg

    def test_default_instances_are_independent(self):
        """Mutable defaults must not be shared between instances."""
        cfg1 = ScanConfig()
        cfg2 = ScanConfig()
        cfg1.disabled_rules.append("MCP001")
        assert cfg2.disabled_rules == []


# ---------------------------------------------------------------------------
# RuleMetadata dataclass tests
# ---------------------------------------------------------------------------


class TestRuleMetadata:
    def test_construction(self):
        meta = RuleMetadata(
            rule_id="MCP001",
            severity=Severity.HIGH,
            cwe="CWE-918",
            title="Tainted URL SSRF",
            description="HTTP client called with tainted URL.",
            remediation="Validate URL against allowlist.",
        )
        assert meta.rule_id == "MCP001"
        assert meta.cwe == "CWE-918"
        assert meta.severity == Severity.HIGH
