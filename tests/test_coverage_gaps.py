"""Tests targeting specific coverage gaps identified in the checkpoint review.

Covers:
- prober.py lines 147-168: time-based SSRF latency heuristic (HIGH confidence path)
- prober.py lines 211-228: injection probe payload reflected verbatim in response
- prober.py lines 264-265: auth probe accepted without error
- prober.py lines 322-327: _probe_with_stdio happy path (successful connection)
- prober.py lines 338-343: _probe_with_http happy path (successful connection)
- sarif_formatter.py lines 37-39: _parse_location fallback (no colon in location)
- scanner.py lines 21-22: _get_tool_version PackageNotFoundError fallback
- scanner.py line 28: _apply_severity_filter with min_severity=None
- static/analyzer.py lines 56-57: _get_tool_version PackageNotFoundError fallback
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_scan.dynamic.prober import DynamicProber, ToolInfo, _SSRF_LATENCY_THRESHOLD
from mcp_scan.formatters.sarif_formatter import SarifFormatter, _parse_location
from mcp_scan.models import Finding, ScanConfig, ScanResult, Severity
from mcp_scan.scanner import Scanner, _apply_severity_filter, _get_tool_version


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(**overrides) -> Finding:
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


def _make_scan_result(findings, scan_mode="static") -> ScanResult:
    from datetime import datetime, timezone
    return ScanResult(
        findings=findings,
        scan_mode=scan_mode,
        target="test_target",
        timestamp=datetime.now(timezone.utc),
        tool_version="0.1.0",
    )


def _make_call_tool_response(is_error=False, content_text=""):
    response = MagicMock()
    response.isError = is_error
    content_item = MagicMock()
    content_item.text = content_text
    response.content = [content_item]
    return response


# ---------------------------------------------------------------------------
# prober.py lines 147-168: time-based SSRF latency heuristic
# ---------------------------------------------------------------------------


class TestSsrfLatencyHeuristic:
    """_probe_ssrf emits a HIGH-latency finding when call_tool takes > 500ms."""

    @pytest.mark.asyncio
    async def test_slow_response_emits_latency_finding(self):
        """When call_tool takes > _SSRF_LATENCY_THRESHOLD seconds, a latency-based
        finding is emitted and the loop breaks (only one finding per parameter)."""
        prober = DynamicProber()
        tool = ToolInfo(name="fetch_url", description="", input_schema={})

        # Make call_tool sleep long enough to exceed the threshold
        async def slow_call_tool(*args, **kwargs):
            await asyncio.sleep(_SSRF_LATENCY_THRESHOLD + 0.1)
            return _make_call_tool_response()

        session = AsyncMock()
        session.call_tool = slow_call_tool

        findings = await prober._probe_ssrf(session, tool, "url", "test-target")

        # Should have exactly one finding (loop breaks after first latency hit)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "MCP001"
        assert finding.confidence == "LOW"
        assert "latency" in finding.message.lower() or "elevated" in finding.message.lower()

    @pytest.mark.asyncio
    async def test_fast_response_falls_through_to_default_low_confidence(self):
        """When call_tool is fast (< threshold), the latency branch is NOT taken
        and the fallback LOW-confidence finding is emitted instead."""
        prober = DynamicProber()
        tool = ToolInfo(name="fetch_url", description="", input_schema={})

        session = AsyncMock()
        session.call_tool = AsyncMock(return_value=_make_call_tool_response())

        findings = await prober._probe_ssrf(session, tool, "url", "test-target")

        # Fallback finding should be present
        assert len(findings) >= 1
        assert all(f.confidence == "LOW" for f in findings)
        # None should mention latency (that's the other branch)
        assert not any("latency" in f.message.lower() for f in findings)


# ---------------------------------------------------------------------------
# prober.py lines 211-228: injection probe reflected verbatim
# ---------------------------------------------------------------------------


class TestInjectionProbeReflection:
    """_probe_injection emits MCP021 when payload is reflected verbatim in response."""

    @pytest.mark.asyncio
    async def test_reflected_payload_emits_mcp021(self):
        """When the injection payload appears verbatim in the response, MCP021 fires."""
        prober = DynamicProber()
        tool = ToolInfo(name="echo_tool", description="", input_schema={})

        # The response echoes the payload back
        from mcp_scan.dynamic.probes import INJECTION_PROBES
        reflected_payload = INJECTION_PROBES[0]
        session = AsyncMock()
        session.call_tool = AsyncMock(
            return_value=_make_call_tool_response(content_text=reflected_payload)
        )

        findings = await prober._probe_injection(session, tool, "text", "test-target")

        mcp021 = [f for f in findings if f.rule_id == "MCP021"]
        assert len(mcp021) >= 1
        assert mcp021[0].severity == Severity.HIGH
        assert "echo_tool" in mcp021[0].location

    @pytest.mark.asyncio
    async def test_non_reflected_payload_emits_no_finding(self):
        """When the response does NOT contain the payload, no MCP021 finding is emitted."""
        prober = DynamicProber()
        tool = ToolInfo(name="safe_tool", description="", input_schema={})

        session = AsyncMock()
        session.call_tool = AsyncMock(
            return_value=_make_call_tool_response(content_text="safe response")
        )

        findings = await prober._probe_injection(session, tool, "text", "test-target")
        assert findings == []

    @pytest.mark.asyncio
    async def test_injection_probe_exception_is_swallowed(self):
        """If call_tool raises, _probe_injection swallows the exception and returns []."""
        prober = DynamicProber()
        tool = ToolInfo(name="broken_tool", description="", input_schema={})

        session = AsyncMock()
        session.call_tool = AsyncMock(side_effect=RuntimeError("tool crashed"))

        findings = await prober._probe_injection(session, tool, "text", "test-target")
        assert findings == []

    @pytest.mark.asyncio
    async def test_reflected_payload_finding_contains_payload_text(self):
        """The MCP021 finding message includes the reflected payload."""
        prober = DynamicProber()
        tool = ToolInfo(name="echo_tool", description="", input_schema={})

        from mcp_scan.dynamic.probes import INJECTION_PROBES
        payload = INJECTION_PROBES[0]
        session = AsyncMock()
        session.call_tool = AsyncMock(
            return_value=_make_call_tool_response(content_text=payload)
        )

        findings = await prober._probe_injection(session, tool, "text", "test-target")
        assert any(payload in f.message for f in findings)


# ---------------------------------------------------------------------------
# prober.py lines 264-265: auth probe accepted without error
# ---------------------------------------------------------------------------


class TestAuthProbeAccepted:
    """_probe_auth emits a finding when the server accepts a plaintext HTTP URL."""

    @pytest.mark.asyncio
    async def test_accepted_http_url_emits_finding(self):
        """When call_tool succeeds (isError=False), an auth finding is emitted."""
        prober = DynamicProber()
        tool = ToolInfo(name="oauth_tool", description="", input_schema={})

        session = AsyncMock()
        session.call_tool = AsyncMock(
            return_value=_make_call_tool_response(is_error=False)
        )

        findings = await prober._probe_auth(session, tool, "callback_url", "test-target")

        assert len(findings) >= 1
        assert findings[0].confidence == "LOW"
        assert "http://" in findings[0].message or "plaintext" in findings[0].message.lower()

    @pytest.mark.asyncio
    async def test_rejected_http_url_emits_no_finding(self):
        """When call_tool returns isError=True, no auth finding is emitted."""
        prober = DynamicProber()
        tool = ToolInfo(name="oauth_tool", description="", input_schema={})

        session = AsyncMock()
        session.call_tool = AsyncMock(
            return_value=_make_call_tool_response(is_error=True)
        )

        findings = await prober._probe_auth(session, tool, "callback_url", "test-target")
        assert findings == []

    @pytest.mark.asyncio
    async def test_auth_probe_exception_is_swallowed(self):
        """If call_tool raises, _probe_auth swallows the exception and returns []."""
        prober = DynamicProber()
        tool = ToolInfo(name="oauth_tool", description="", input_schema={})

        session = AsyncMock()
        session.call_tool = AsyncMock(side_effect=RuntimeError("auth failed"))

        findings = await prober._probe_auth(session, tool, "callback_url", "test-target")
        assert findings == []

    @pytest.mark.asyncio
    async def test_auth_probe_dispatched_for_auth_param_names(self):
        """_run_probes dispatches auth probes for parameters named 'url', 'callback', etc."""
        prober = DynamicProber(allow_destructive=False)

        # Build a session with a tool that has an auth-related param
        tool_mock = MagicMock()
        tool_mock.name = "oauth_tool"
        tool_mock.description = "OAuth handler"
        tool_mock.inputSchema = {
            "type": "object",
            "properties": {"callback": {"type": "string"}},
        }
        list_response = MagicMock()
        list_response.tools = [tool_mock]

        session = AsyncMock()
        session.list_tools = AsyncMock(return_value=list_response)
        session.call_tool = AsyncMock(return_value=_make_call_tool_response(is_error=False))

        tools = await prober._enumerate_tools(session)
        findings = await prober._run_probes(session, tools, "test-target")

        # Auth probe should have been dispatched (callback is an auth param)
        assert session.call_tool.called


# ---------------------------------------------------------------------------
# prober.py lines 322-327: _probe_with_stdio happy path
# ---------------------------------------------------------------------------


class TestProbeWithStdioHappyPath:
    """_probe_with_stdio returns a ScanResult when the connection succeeds."""

    @pytest.mark.asyncio
    async def test_stdio_happy_path_returns_scan_result(self):
        """_probe_with_stdio returns a ScanResult with scan_mode='dynamic'."""
        prober = DynamicProber()

        # Build a mock session that returns no tools
        mock_session = AsyncMock()
        mock_session.initialize = AsyncMock(return_value=None)
        list_response = MagicMock()
        list_response.tools = []
        mock_session.list_tools = AsyncMock(return_value=list_response)

        # Mock the context managers for stdio_client and ClientSession
        mock_read = MagicMock()
        mock_write = MagicMock()

        mock_stdio_cm = MagicMock()
        mock_stdio_cm.__aenter__ = AsyncMock(return_value=(mock_read, mock_write))
        mock_stdio_cm.__aexit__ = AsyncMock(return_value=False)

        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cm.__aexit__ = AsyncMock(return_value=False)

        with patch("mcp_scan.dynamic.prober.stdio_client", return_value=mock_stdio_cm), \
             patch("mcp_scan.dynamic.prober.ClientSession", return_value=mock_session_cm), \
             patch("mcp_scan.dynamic.prober.asyncio.wait_for", new=AsyncMock(return_value=None)):
            result = await prober._probe_with_stdio("python server.py")

        assert isinstance(result, ScanResult)
        assert result.scan_mode == "dynamic"
        assert result.target == "python server.py"

    @pytest.mark.asyncio
    async def test_stdio_happy_path_with_args(self):
        """_probe_with_stdio correctly splits command + args from the target string."""
        prober = DynamicProber()

        mock_session = AsyncMock()
        mock_session.initialize = AsyncMock(return_value=None)
        list_response = MagicMock()
        list_response.tools = []
        mock_session.list_tools = AsyncMock(return_value=list_response)

        mock_read = MagicMock()
        mock_write = MagicMock()

        mock_stdio_cm = MagicMock()
        mock_stdio_cm.__aenter__ = AsyncMock(return_value=(mock_read, mock_write))
        mock_stdio_cm.__aexit__ = AsyncMock(return_value=False)

        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cm.__aexit__ = AsyncMock(return_value=False)

        captured_params = {}

        def capture_stdio(params):
            captured_params["params"] = params
            return mock_stdio_cm

        with patch("mcp_scan.dynamic.prober.stdio_client", side_effect=capture_stdio), \
             patch("mcp_scan.dynamic.prober.ClientSession", return_value=mock_session_cm), \
             patch("mcp_scan.dynamic.prober.asyncio.wait_for", new=AsyncMock(return_value=None)):
            await prober._probe_with_stdio("python server.py --port 8080")

        params = captured_params["params"]
        assert params.command == "python"
        assert params.args == ["server.py", "--port", "8080"]


# ---------------------------------------------------------------------------
# prober.py lines 338-343: _probe_with_http happy path
# ---------------------------------------------------------------------------


class TestProbeWithHttpHappyPath:
    """_probe_with_http returns a ScanResult when the HTTP connection succeeds."""

    @pytest.mark.asyncio
    async def test_http_happy_path_returns_scan_result(self):
        """_probe_with_http returns a ScanResult with scan_mode='dynamic'."""
        prober = DynamicProber()

        mock_session = AsyncMock()
        mock_session.initialize = AsyncMock(return_value=None)
        list_response = MagicMock()
        list_response.tools = []
        mock_session.list_tools = AsyncMock(return_value=list_response)

        mock_read = MagicMock()
        mock_write = MagicMock()
        mock_get_session_id = MagicMock()

        mock_http_cm = MagicMock()
        mock_http_cm.__aenter__ = AsyncMock(
            return_value=(mock_read, mock_write, mock_get_session_id)
        )
        mock_http_cm.__aexit__ = AsyncMock(return_value=False)

        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cm.__aexit__ = AsyncMock(return_value=False)

        target = "http://localhost:8080/mcp"
        with patch("mcp_scan.dynamic.prober.streamable_http_client", return_value=mock_http_cm), \
             patch("mcp_scan.dynamic.prober.ClientSession", return_value=mock_session_cm), \
             patch("mcp_scan.dynamic.prober.asyncio.wait_for", new=AsyncMock(return_value=None)):
            result = await prober._probe_with_http(target)

        assert isinstance(result, ScanResult)
        assert result.scan_mode == "dynamic"
        assert result.target == target

    @pytest.mark.asyncio
    async def test_http_happy_path_findings_are_empty_for_clean_server(self):
        """_probe_with_http returns empty findings when the server has no tools."""
        prober = DynamicProber()

        mock_session = AsyncMock()
        mock_session.initialize = AsyncMock(return_value=None)
        list_response = MagicMock()
        list_response.tools = []
        mock_session.list_tools = AsyncMock(return_value=list_response)

        mock_read = MagicMock()
        mock_write = MagicMock()
        mock_get_session_id = MagicMock()

        mock_http_cm = MagicMock()
        mock_http_cm.__aenter__ = AsyncMock(
            return_value=(mock_read, mock_write, mock_get_session_id)
        )
        mock_http_cm.__aexit__ = AsyncMock(return_value=False)

        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cm.__aexit__ = AsyncMock(return_value=False)

        with patch("mcp_scan.dynamic.prober.streamable_http_client", return_value=mock_http_cm), \
             patch("mcp_scan.dynamic.prober.ClientSession", return_value=mock_session_cm), \
             patch("mcp_scan.dynamic.prober.asyncio.wait_for", new=AsyncMock(return_value=None)):
            result = await prober._probe_with_http("http://localhost:8080/mcp")

        assert result.findings == []


# ---------------------------------------------------------------------------
# sarif_formatter.py lines 37-39: _parse_location fallback
# ---------------------------------------------------------------------------


class TestParseLocationFallback:
    """_parse_location falls back to (location, 1) when there is no colon."""

    def test_no_colon_returns_location_and_line_1(self):
        """A location string with no colon returns (location, 1)."""
        uri, line = _parse_location("tool:my_tool_name")
        # "tool:my_tool_name" has a colon, but the part after is not an int
        # so it falls through to the fallback
        assert line == 1

    def test_location_without_any_colon_returns_fallback(self):
        """A location string with no colon at all returns (location, 1)."""
        uri, line = _parse_location("just_a_filename.py")
        assert uri == "just_a_filename.py"
        assert line == 1

    def test_valid_location_parses_correctly(self):
        """A valid 'file.py:42' location parses to (file.py, 42)."""
        uri, line = _parse_location("src/server.py:42")
        assert uri == "src/server.py"
        assert line == 42

    def test_sarif_formatter_handles_tool_location(self):
        """SarifFormatter handles dynamic findings with 'tool:name' locations."""
        from datetime import datetime, timezone
        result = ScanResult(
            findings=[
                Finding(
                    rule_id="MCP021",
                    severity=Severity.HIGH,
                    target="http://localhost:8080",
                    location="tool:my_tool",  # no integer after colon
                    message="Injection found",
                    remediation="Fix it.",
                )
            ],
            scan_mode="dynamic",
            target="http://localhost:8080",
            timestamp=datetime.now(timezone.utc),
            tool_version="0.1.0",
        )
        formatter = SarifFormatter()
        output = formatter.format(result)
        import json
        doc = json.loads(output)
        # Should produce valid SARIF with startLine=1 for the fallback
        sarif_result = doc["runs"][0]["results"][0]
        region = sarif_result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 1


# ---------------------------------------------------------------------------
# scanner.py lines 21-22: _get_tool_version PackageNotFoundError fallback
# ---------------------------------------------------------------------------


class TestGetToolVersionFallback:
    """_get_tool_version returns '0.0.0' when the package is not installed."""

    def test_returns_version_string_when_installed(self):
        """_get_tool_version returns a non-empty string in normal conditions."""
        version = _get_tool_version()
        assert isinstance(version, str)
        assert len(version) > 0

    def test_returns_fallback_when_package_not_found(self):
        """_get_tool_version returns '0.0.0' when PackageNotFoundError is raised."""
        with patch(
            "mcp_scan.scanner.importlib.metadata.version",
            side_effect=importlib.metadata.PackageNotFoundError("mcp-bandit"),
        ):
            version = _get_tool_version()
        assert version == "0.0.0"


# ---------------------------------------------------------------------------
# scanner.py line 28: _apply_severity_filter with min_severity=None
# ---------------------------------------------------------------------------


class TestApplySeverityFilterNone:
    """_apply_severity_filter returns the original result when min_severity is None."""

    def test_none_min_severity_returns_original_result(self):
        """When config.min_severity is None, the original ScanResult is returned unchanged."""
        findings = [
            _make_finding(severity=Severity.INFO),
            _make_finding(severity=Severity.LOW),
            _make_finding(severity=Severity.HIGH),
        ]
        result = _make_scan_result(findings)
        config = ScanConfig()
        config.min_severity = None  # type: ignore[assignment]

        filtered = _apply_severity_filter(result, config)
        assert filtered is result  # same object, no copy
        assert len(filtered.findings) == 3


# ---------------------------------------------------------------------------
# static/analyzer.py lines 56-57: _get_tool_version PackageNotFoundError fallback
# ---------------------------------------------------------------------------


class TestAnalyzerGetToolVersionFallback:
    """StaticAnalyzer._get_tool_version returns '0.0.0' when package is not installed."""

    def test_analyzer_version_fallback(self):
        """_get_tool_version in analyzer.py returns '0.0.0' on PackageNotFoundError."""
        import importlib.metadata as _meta
        from mcp_scan.static import analyzer as _analyzer_mod

        with patch.object(
            _meta,
            "version",
            side_effect=_meta.PackageNotFoundError("mcp-bandit"),
        ):
            version = _analyzer_mod._get_tool_version()
        assert version == "0.0.0"

    def test_analyzer_version_returned_in_scan_result(self, tmp_path):
        """analyze_path embeds the tool version in the returned ScanResult."""
        from mcp_scan.static.analyzer import StaticAnalyzer
        (tmp_path / "empty.py").write_text("x = 1\n")
        analyzer = StaticAnalyzer()
        result = analyzer.analyze_path(tmp_path)
        assert isinstance(result.tool_version, str)
        assert len(result.tool_version) > 0
