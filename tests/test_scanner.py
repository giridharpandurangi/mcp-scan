"""Unit tests for the Scanner facade.

Task 12.1 — Requirements 10.3, 11.2, 11.3

Tests cover:
- scan_static delegates to StaticAnalyzer and returns ScanResult
- scan_all merges findings from both analyzers
- disabled_rules are not executed
- min_severity filter is applied
"""

from __future__ import annotations

import ast
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_scan.models import Finding, ScanConfig, ScanResult, Severity
from mcp_scan.rules import Rule
from mcp_scan.scanner import Scanner, _apply_severity_filter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_py(tmp_path: Path, rel_path: str, source: str) -> Path:
    """Write *source* to *tmp_path / rel_path*, creating parent dirs as needed."""
    target = tmp_path / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(textwrap.dedent(source), encoding="utf-8")
    return target


def _make_finding(**overrides) -> Finding:
    """Return a Finding with sensible defaults, overridable via kwargs."""
    defaults = dict(
        rule_id="MCP001",
        severity=Severity.HIGH,
        target="src/server.py",
        location="src/server.py:10",
        message="Test finding",
        remediation="Fix it.",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _make_scan_result(findings: list[Finding], scan_mode: str = "static") -> ScanResult:
    """Return a ScanResult with the given findings."""
    return ScanResult(
        findings=findings,
        scan_mode=scan_mode,  # type: ignore[arg-type]
        target="test_target",
        timestamp=datetime.now(timezone.utc),
        tool_version="0.1.0",
    )


# ---------------------------------------------------------------------------
# _apply_severity_filter helper
# ---------------------------------------------------------------------------


class TestApplySeverityFilter:
    """Tests for the _apply_severity_filter helper function."""

    def test_no_filter_returns_all_findings(self):
        """With min_severity=INFO (default), all findings are returned."""
        findings = [
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.MEDIUM),
            _make_finding(severity=Severity.LOW),
            _make_finding(severity=Severity.INFO),
        ]
        result = _make_scan_result(findings)
        config = ScanConfig(min_severity=Severity.INFO)
        filtered = _apply_severity_filter(result, config)
        assert len(filtered.findings) == 5

    def test_min_severity_high_removes_lower(self):
        """min_severity=HIGH keeps only HIGH and CRITICAL findings."""
        findings = [
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.MEDIUM),
            _make_finding(severity=Severity.LOW),
            _make_finding(severity=Severity.INFO),
        ]
        result = _make_scan_result(findings)
        config = ScanConfig(min_severity=Severity.HIGH)
        filtered = _apply_severity_filter(result, config)
        assert len(filtered.findings) == 2
        assert all(f.severity >= Severity.HIGH for f in filtered.findings)

    def test_min_severity_critical_keeps_only_critical(self):
        """min_severity=CRITICAL keeps only CRITICAL findings."""
        findings = [
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.MEDIUM),
        ]
        result = _make_scan_result(findings)
        config = ScanConfig(min_severity=Severity.CRITICAL)
        filtered = _apply_severity_filter(result, config)
        assert len(filtered.findings) == 1
        assert filtered.findings[0].severity == Severity.CRITICAL

    def test_filter_preserves_scan_mode_and_metadata(self):
        """Filtering does not change scan_mode, target, or tool_version."""
        findings = [_make_finding(severity=Severity.INFO)]
        result = _make_scan_result(findings, scan_mode="static")
        config = ScanConfig(min_severity=Severity.HIGH)
        filtered = _apply_severity_filter(result, config)
        assert filtered.scan_mode == "static"
        assert filtered.target == result.target
        assert filtered.tool_version == result.tool_version

    def test_filter_returns_same_object_when_nothing_removed(self):
        """When no findings are removed, the same ScanResult object is returned."""
        findings = [_make_finding(severity=Severity.HIGH)]
        result = _make_scan_result(findings)
        config = ScanConfig(min_severity=Severity.INFO)
        filtered = _apply_severity_filter(result, config)
        assert filtered is result  # identity check — no copy needed

    def test_filter_empty_findings_returns_empty(self):
        """Filtering a result with no findings returns an empty findings list."""
        result = _make_scan_result([])
        config = ScanConfig(min_severity=Severity.HIGH)
        filtered = _apply_severity_filter(result, config)
        assert filtered.findings == []


# ---------------------------------------------------------------------------
# Scanner.scan_static
# ---------------------------------------------------------------------------


class TestScanStatic:
    """Tests for Scanner.scan_static()."""

    def test_scan_static_returns_scan_result(self, tmp_path):
        """scan_static returns a ScanResult with scan_mode='static'."""
        _write_py(tmp_path, "server.py", "x = 1\n")
        scanner = Scanner()
        result = scanner.scan_static(tmp_path)
        assert isinstance(result, ScanResult)
        assert result.scan_mode == "static"

    def test_scan_static_delegates_to_static_analyzer(self, tmp_path):
        """scan_static delegates to StaticAnalyzer.analyze_path."""
        _write_py(tmp_path, "server.py", "x = 1\n")
        scanner = Scanner()

        with patch("mcp_scan.scanner.StaticAnalyzer") as MockAnalyzer:
            mock_instance = MagicMock()
            mock_instance.analyze_path.return_value = _make_scan_result([])
            MockAnalyzer.return_value = mock_instance

            result = scanner.scan_static(tmp_path)

            MockAnalyzer.assert_called_once()
            mock_instance.analyze_path.assert_called_once_with(tmp_path)
            assert isinstance(result, ScanResult)

    def test_scan_static_passes_config_to_analyzer(self, tmp_path):
        """scan_static passes the ScanConfig to StaticAnalyzer."""
        _write_py(tmp_path, "server.py", "x = 1\n")
        config = ScanConfig(disabled_rules=["MCP001"], min_severity=Severity.HIGH)
        scanner = Scanner(config=config)

        with patch("mcp_scan.scanner.StaticAnalyzer") as MockAnalyzer:
            mock_instance = MagicMock()
            mock_instance.analyze_path.return_value = _make_scan_result([])
            MockAnalyzer.return_value = mock_instance

            scanner.scan_static(tmp_path)

            # Config should be passed to StaticAnalyzer constructor
            call_kwargs = MockAnalyzer.call_args
            assert call_kwargs is not None
            # config is passed as keyword argument
            passed_config = call_kwargs.kwargs.get("config") or (
                call_kwargs.args[1] if len(call_kwargs.args) > 1 else None
            )
            assert passed_config is config

    def test_scan_static_applies_min_severity_filter(self, tmp_path):
        """scan_static filters out findings below min_severity."""
        _write_py(tmp_path, "server.py", "x = 1\n")
        config = ScanConfig(min_severity=Severity.HIGH)
        scanner = Scanner(config=config)

        low_finding = _make_finding(severity=Severity.LOW)
        high_finding = _make_finding(severity=Severity.HIGH)

        with patch("mcp_scan.scanner.StaticAnalyzer") as MockAnalyzer:
            mock_instance = MagicMock()
            mock_instance.analyze_path.return_value = _make_scan_result(
                [low_finding, high_finding]
            )
            MockAnalyzer.return_value = mock_instance

            result = scanner.scan_static(tmp_path)

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH

    def test_scan_static_with_no_config_uses_defaults(self, tmp_path):
        """Scanner with no config uses ScanConfig defaults (min_severity=INFO)."""
        _write_py(tmp_path, "server.py", "x = 1\n")
        scanner = Scanner()
        assert scanner.config.min_severity == Severity.INFO
        assert scanner.config.disabled_rules == []

    def test_scan_static_target_is_path_string(self, tmp_path):
        """The ScanResult target reflects the path passed to scan_static."""
        _write_py(tmp_path, "server.py", "x = 1\n")
        scanner = Scanner()
        result = scanner.scan_static(tmp_path)
        assert result.target == str(tmp_path)

    def test_scan_static_with_real_vulnerable_file(self, tmp_path):
        """scan_static detects a real vulnerability in a fixture file."""
        source = textwrap.dedent("""\
            import httpx

            @mcp.tool()
            def fetch_data(url):
                return httpx.get(url)
        """)
        _write_py(tmp_path, "server.py", source)
        scanner = Scanner()
        result = scanner.scan_static(tmp_path)
        assert isinstance(result, ScanResult)
        # MCP001 should fire for tainted URL
        rule_ids = {f.rule_id for f in result.findings}
        assert "MCP001" in rule_ids


# ---------------------------------------------------------------------------
# Scanner.scan_static — disabled_rules filter
# ---------------------------------------------------------------------------


class TestScanStaticDisabledRules:
    """Tests that disabled_rules in ScanConfig prevents those rules from running."""

    def test_disabled_rule_not_in_findings(self, tmp_path):
        """A rule listed in disabled_rules produces no findings."""
        source = textwrap.dedent("""\
            import httpx

            @mcp.tool()
            def fetch_data(url):
                return httpx.get(url)
        """)
        _write_py(tmp_path, "server.py", source)

        # Disable MCP001 — the SSRF rule that would fire on this file
        config = ScanConfig(disabled_rules=["MCP001"])
        scanner = Scanner(config=config)
        result = scanner.scan_static(tmp_path)

        rule_ids = {f.rule_id for f in result.findings}
        assert "MCP001" not in rule_ids

    def test_non_disabled_rules_still_run(self, tmp_path):
        """Rules not in disabled_rules still produce findings."""
        source = textwrap.dedent("""\
            import httpx

            @mcp.tool()
            def fetch_data(url):
                return httpx.get(url)
        """)
        _write_py(tmp_path, "server.py", source)

        # Disable only MCP002 — MCP001 should still fire
        config = ScanConfig(disabled_rules=["MCP002"])
        scanner = Scanner(config=config)
        result = scanner.scan_static(tmp_path)

        rule_ids = {f.rule_id for f in result.findings}
        assert "MCP001" in rule_ids

    def test_all_rules_disabled_produces_no_findings(self, tmp_path):
        """Disabling all rules produces zero findings."""
        source = textwrap.dedent("""\
            import httpx

            @mcp.tool()
            def fetch_data(url):
                return httpx.get(url)
        """)
        _write_py(tmp_path, "server.py", source)

        # Disable all known rules
        all_rule_ids = [
            "MCP001", "MCP002", "MCP003", "MCP004", "MCP005",
            "MCP010", "MCP011", "MCP012", "MCP013", "MCP014",
            "MCP020", "MCP021",
        ]
        config = ScanConfig(disabled_rules=all_rule_ids)
        scanner = Scanner(config=config)
        result = scanner.scan_static(tmp_path)

        # No rule findings (PARSE_ERROR is not a rule, so it won't appear either)
        rule_findings = [f for f in result.findings if f.rule_id in all_rule_ids]
        assert rule_findings == []


# ---------------------------------------------------------------------------
# Scanner.scan_dynamic
# ---------------------------------------------------------------------------


class TestScanDynamic:
    """Tests for Scanner.scan_dynamic()."""

    @pytest.mark.asyncio
    async def test_scan_dynamic_returns_scan_result(self):
        """scan_dynamic returns a ScanResult with scan_mode='dynamic'."""
        scanner = Scanner()

        with patch("mcp_scan.dynamic.prober.DynamicProber") as MockProber:
            mock_instance = AsyncMock()
            mock_instance.probe.return_value = _make_scan_result([], scan_mode="dynamic")
            MockProber.return_value = mock_instance

            result = await scanner.scan_dynamic("python server.py")

        assert isinstance(result, ScanResult)
        assert result.scan_mode == "dynamic"

    @pytest.mark.asyncio
    async def test_scan_dynamic_delegates_to_dynamic_prober(self):
        """scan_dynamic delegates to DynamicProber.probe."""
        scanner = Scanner()
        target = "python server.py"

        with patch("mcp_scan.dynamic.prober.DynamicProber") as MockProber:
            mock_instance = AsyncMock()
            mock_instance.probe.return_value = _make_scan_result([], scan_mode="dynamic")
            MockProber.return_value = mock_instance

            await scanner.scan_dynamic(target)

            MockProber.assert_called_once()
            mock_instance.probe.assert_called_once_with(target)

    @pytest.mark.asyncio
    async def test_scan_dynamic_applies_min_severity_filter(self):
        """scan_dynamic filters out findings below min_severity."""
        config = ScanConfig(min_severity=Severity.HIGH)
        scanner = Scanner(config=config)

        low_finding = _make_finding(severity=Severity.LOW)
        high_finding = _make_finding(severity=Severity.HIGH)

        with patch("mcp_scan.dynamic.prober.DynamicProber") as MockProber:
            mock_instance = AsyncMock()
            mock_instance.probe.return_value = _make_scan_result(
                [low_finding, high_finding], scan_mode="dynamic"
            )
            MockProber.return_value = mock_instance

            result = await scanner.scan_dynamic("python server.py")

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Scanner.scan_all
# ---------------------------------------------------------------------------


class TestScanAll:
    """Tests for Scanner.scan_all()."""

    @pytest.mark.asyncio
    async def test_scan_all_returns_scan_result_with_mode_all(self, tmp_path):
        """scan_all returns a ScanResult with scan_mode='all'."""
        _write_py(tmp_path, "server.py", "x = 1\n")
        scanner = Scanner()

        with patch("mcp_scan.scanner.StaticAnalyzer") as MockAnalyzer, \
             patch("mcp_scan.dynamic.prober.DynamicProber") as MockProber:
            mock_analyzer = MagicMock()
            mock_analyzer.analyze_path.return_value = _make_scan_result([])
            MockAnalyzer.return_value = mock_analyzer

            mock_prober = AsyncMock()
            mock_prober.probe.return_value = _make_scan_result([], scan_mode="dynamic")
            MockProber.return_value = mock_prober

            result = await scanner.scan_all(tmp_path, "python server.py")

        assert isinstance(result, ScanResult)
        assert result.scan_mode == "all"

    @pytest.mark.asyncio
    async def test_scan_all_merges_findings_from_both_analyzers(self, tmp_path):
        """scan_all merges findings from StaticAnalyzer and DynamicProber."""
        _write_py(tmp_path, "server.py", "x = 1\n")
        scanner = Scanner()

        static_finding = _make_finding(rule_id="MCP001", severity=Severity.HIGH)
        dynamic_finding = _make_finding(rule_id="MCP021", severity=Severity.HIGH)

        with patch("mcp_scan.scanner.StaticAnalyzer") as MockAnalyzer, \
             patch("mcp_scan.dynamic.prober.DynamicProber") as MockProber:
            mock_analyzer = MagicMock()
            mock_analyzer.analyze_path.return_value = _make_scan_result([static_finding])
            MockAnalyzer.return_value = mock_analyzer

            mock_prober = AsyncMock()
            mock_prober.probe.return_value = _make_scan_result(
                [dynamic_finding], scan_mode="dynamic"
            )
            MockProber.return_value = mock_prober

            result = await scanner.scan_all(tmp_path, "python server.py")

        assert len(result.findings) == 2
        rule_ids = {f.rule_id for f in result.findings}
        assert "MCP001" in rule_ids
        assert "MCP021" in rule_ids

    @pytest.mark.asyncio
    async def test_scan_all_calls_both_analyzers(self, tmp_path):
        """scan_all calls both StaticAnalyzer.analyze_path and DynamicProber.probe."""
        _write_py(tmp_path, "server.py", "x = 1\n")
        scanner = Scanner()
        target = "python server.py"

        with patch("mcp_scan.scanner.StaticAnalyzer") as MockAnalyzer, \
             patch("mcp_scan.dynamic.prober.DynamicProber") as MockProber:
            mock_analyzer = MagicMock()
            mock_analyzer.analyze_path.return_value = _make_scan_result([])
            MockAnalyzer.return_value = mock_analyzer

            mock_prober = AsyncMock()
            mock_prober.probe.return_value = _make_scan_result([], scan_mode="dynamic")
            MockProber.return_value = mock_prober

            await scanner.scan_all(tmp_path, target)

            mock_analyzer.analyze_path.assert_called_once_with(tmp_path)
            mock_prober.probe.assert_called_once_with(target)

    @pytest.mark.asyncio
    async def test_scan_all_applies_min_severity_filter_to_merged_result(self, tmp_path):
        """scan_all applies min_severity filter to the merged findings."""
        _write_py(tmp_path, "server.py", "x = 1\n")
        config = ScanConfig(min_severity=Severity.HIGH)
        scanner = Scanner(config=config)

        static_low = _make_finding(rule_id="MCP002", severity=Severity.LOW)
        static_high = _make_finding(rule_id="MCP001", severity=Severity.HIGH)
        dynamic_medium = _make_finding(rule_id="MCP021", severity=Severity.MEDIUM)
        dynamic_critical = _make_finding(rule_id="MCP004", severity=Severity.CRITICAL)

        with patch("mcp_scan.scanner.StaticAnalyzer") as MockAnalyzer, \
             patch("mcp_scan.dynamic.prober.DynamicProber") as MockProber:
            mock_analyzer = MagicMock()
            mock_analyzer.analyze_path.return_value = _make_scan_result(
                [static_low, static_high]
            )
            MockAnalyzer.return_value = mock_analyzer

            mock_prober = AsyncMock()
            mock_prober.probe.return_value = _make_scan_result(
                [dynamic_medium, dynamic_critical], scan_mode="dynamic"
            )
            MockProber.return_value = mock_prober

            result = await scanner.scan_all(tmp_path, "python server.py")

        # Only HIGH and CRITICAL should remain
        assert len(result.findings) == 2
        assert all(f.severity >= Severity.HIGH for f in result.findings)

    @pytest.mark.asyncio
    async def test_scan_all_with_empty_findings_from_both(self, tmp_path):
        """scan_all with no findings from either analyzer returns empty findings."""
        _write_py(tmp_path, "server.py", "x = 1\n")
        scanner = Scanner()

        with patch("mcp_scan.scanner.StaticAnalyzer") as MockAnalyzer, \
             patch("mcp_scan.dynamic.prober.DynamicProber") as MockProber:
            mock_analyzer = MagicMock()
            mock_analyzer.analyze_path.return_value = _make_scan_result([])
            MockAnalyzer.return_value = mock_analyzer

            mock_prober = AsyncMock()
            mock_prober.probe.return_value = _make_scan_result([], scan_mode="dynamic")
            MockProber.return_value = mock_prober

            result = await scanner.scan_all(tmp_path, "python server.py")

        assert result.findings == []
        assert result.scan_mode == "all"

    @pytest.mark.asyncio
    async def test_scan_all_passes_config_to_static_analyzer(self, tmp_path):
        """scan_all passes the ScanConfig to StaticAnalyzer."""
        _write_py(tmp_path, "server.py", "x = 1\n")
        config = ScanConfig(disabled_rules=["MCP001"])
        scanner = Scanner(config=config)

        with patch("mcp_scan.scanner.StaticAnalyzer") as MockAnalyzer, \
             patch("mcp_scan.dynamic.prober.DynamicProber") as MockProber:
            mock_analyzer = MagicMock()
            mock_analyzer.analyze_path.return_value = _make_scan_result([])
            MockAnalyzer.return_value = mock_analyzer

            mock_prober = AsyncMock()
            mock_prober.probe.return_value = _make_scan_result([], scan_mode="dynamic")
            MockProber.return_value = mock_prober

            await scanner.scan_all(tmp_path, "python server.py")

            call_kwargs = MockAnalyzer.call_args
            passed_config = call_kwargs.kwargs.get("config") or (
                call_kwargs.args[1] if len(call_kwargs.args) > 1 else None
            )
            assert passed_config is config

    @pytest.mark.asyncio
    async def test_scan_all_disabled_rules_not_in_merged_findings(self, tmp_path):
        """Disabled rules produce no findings in scan_all results."""
        source = textwrap.dedent("""\
            import httpx

            @mcp.tool()
            def fetch_data(url):
                return httpx.get(url)
        """)
        _write_py(tmp_path, "server.py", source)

        # Disable MCP001 — the SSRF rule
        config = ScanConfig(disabled_rules=["MCP001"])
        scanner = Scanner(config=config)

        with patch("mcp_scan.dynamic.prober.DynamicProber") as MockProber:
            mock_prober = AsyncMock()
            mock_prober.probe.return_value = _make_scan_result([], scan_mode="dynamic")
            MockProber.return_value = mock_prober

            result = await scanner.scan_all(tmp_path, "python server.py")

        rule_ids = {f.rule_id for f in result.findings}
        assert "MCP001" not in rule_ids


# ---------------------------------------------------------------------------
# Scanner public API
# ---------------------------------------------------------------------------


class TestScannerPublicAPI:
    """Tests for Scanner's public interface and default configuration."""

    def test_scanner_default_config(self):
        """Scanner() with no args uses default ScanConfig."""
        scanner = Scanner()
        assert isinstance(scanner.config, ScanConfig)
        assert scanner.config.min_severity == Severity.INFO
        assert scanner.config.disabled_rules == []
        assert scanner.config.exclude_paths == []

    def test_scanner_accepts_custom_config(self):
        """Scanner accepts a custom ScanConfig."""
        config = ScanConfig(min_severity=Severity.HIGH, disabled_rules=["MCP001"])
        scanner = Scanner(config=config)
        assert scanner.config is config

    def test_scanner_importable_from_top_level(self):
        """Scanner is importable from the mcp_scan top-level package."""
        from mcp_scan import Scanner as TopLevelScanner
        assert TopLevelScanner is Scanner
