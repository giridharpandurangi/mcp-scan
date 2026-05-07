"""DynamicProber: MCP client connection and security probe orchestration."""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client

from mcp_scan.dynamic.probes import (
    AUTH_PROBES,
    DESTRUCTIVE_PATTERNS,
    INJECTION_PROBES,
    SSRF_PROBES,
)
from mcp_scan.models import Finding, ScanResult, Severity
from mcp_scan.rules.injection import INJECTION_PATTERN

# Version string for ScanResult
_TOOL_VERSION = "0.1.0"

# Auth-related parameter name patterns
_AUTH_PARAM_PATTERN = re.compile(
    r"url|endpoint|callback|redirect",
    re.IGNORECASE,
)

# Time-based SSRF heuristic threshold in seconds
_SSRF_LATENCY_THRESHOLD = 0.5


@dataclass
class ToolInfo:
    """Holds information about an enumerated MCP tool."""

    name: str
    description: str
    input_schema: dict


class DynamicProber:
    """Connects to a running MCP server, enumerates tools, and sends crafted probes."""

    def __init__(self, timeout: int = 30, allow_destructive: bool = False) -> None:
        self.timeout = timeout
        self.allow_destructive = allow_destructive

    def _is_destructive_tool(self, tool_name: str) -> bool:
        """Return True if the tool name matches a destructive pattern."""
        return bool(DESTRUCTIVE_PATTERNS.match(tool_name))

    async def _enumerate_tools(self, session: ClientSession) -> list[ToolInfo]:
        """Call list_tools() and extract name, description, and inputSchema."""
        result = await session.list_tools()
        tools: list[ToolInfo] = []
        for tool in result.tools:
            tools.append(ToolInfo(
                name=tool.name,
                description=tool.description or "",
                input_schema=tool.inputSchema if isinstance(tool.inputSchema, dict) else {},
            ))
        return tools

    def _get_string_params(self, tool: ToolInfo) -> list[str]:
        """Return parameter names that are string-typed from the tool's inputSchema."""
        string_params: list[str] = []
        schema = tool.input_schema
        properties = schema.get("properties", {})
        for param_name, param_schema in properties.items():
            if isinstance(param_schema, dict):
                param_type = param_schema.get("type", "")
                if param_type == "string":
                    string_params.append(param_name)
        return string_params

    def _is_auth_param(self, param_name: str) -> bool:
        """Return True if the parameter name looks auth/endpoint-related."""
        return bool(_AUTH_PARAM_PATTERN.search(param_name))

    def _check_description_mcp020(
        self, tool: ToolInfo, target: str
    ) -> Finding | None:
        """Check tool description for Unicode > U+00FF (MCP020)."""
        for char in tool.description:
            if ord(char) > 0xFF:
                return Finding(
                    rule_id="MCP020",
                    severity=Severity.HIGH,
                    target=target,
                    location=f"tool:{tool.name}",
                    message=(
                        f"Tool description for '{tool.name}' contains a non-Latin-1 "
                        f"Unicode character: U+{ord(char):04X} ('{char}'). "
                        "Hidden Unicode may be used to smuggle prompt injection payloads."
                    ),
                    remediation=(
                        "Remove or replace non-Latin-1 Unicode characters from the tool description."
                    ),
                )
        return None

    def _check_description_mcp021(
        self, tool: ToolInfo, target: str
    ) -> Finding | None:
        """Check tool description for injection phrases (MCP021)."""
        match = INJECTION_PATTERN.search(tool.description)
        if match:
            return Finding(
                rule_id="MCP021",
                severity=Severity.HIGH,
                target=target,
                location=f"tool:{tool.name}",
                message=(
                    f"Tool description for '{tool.name}' contains a prompt injection "
                    f"phrase: '{match.group()}'. "
                    "This may be used to manipulate LLM behavior."
                ),
                remediation=(
                    "Remove prompt injection phrases from the tool description."
                ),
            )
        return None

    async def _probe_ssrf(
        self,
        session: ClientSession,
        tool: ToolInfo,
        param_name: str,
        target: str,
    ) -> list[Finding]:
        """Send SSRF probes to a string parameter and emit LOW confidence findings."""
        findings: list[Finding] = []

        for probe_url in SSRF_PROBES:
            try:
                t_start = time.monotonic()
                await session.call_tool(tool.name, {param_name: probe_url})
                elapsed = time.monotonic() - t_start

                # Time-based heuristic: if response took > 500ms, weak SSRF indicator
                if elapsed > _SSRF_LATENCY_THRESHOLD:
                    findings.append(Finding(
                        rule_id="MCP001",
                        severity=Severity.HIGH,
                        target=target,
                        location=f"tool:{tool.name}",
                        message=(
                            f"Tool '{tool.name}' parameter '{param_name}' accepted SSRF probe "
                            f"'{probe_url}' with elevated response latency ({elapsed:.2f}s > "
                            f"{_SSRF_LATENCY_THRESHOLD}s). Weak indicator of SSRF — no "
                            "controlled listener configured to confirm."
                        ),
                        remediation=(
                            "Validate and allowlist URLs before making outbound requests. "
                            "Use --ssrf-listener for confirmed SSRF detection."
                        ),
                        confidence="LOW",
                    ))
                    break  # One finding per tool parameter is sufficient

            except Exception:
                # Probe call failed — not necessarily a finding, skip
                pass

        # Without a controlled listener, always emit a LOW confidence finding
        # to indicate the probe was sent but cannot be confirmed
        if not findings:
            findings.append(Finding(
                rule_id="MCP001",
                severity=Severity.HIGH,
                target=target,
                location=f"tool:{tool.name}",
                message=(
                    f"Tool '{tool.name}' parameter '{param_name}' accepted SSRF probe payloads "
                    f"(e.g., '{SSRF_PROBES[0]}'). No controlled listener configured — "
                    "cannot confirm outbound request. Confidence: LOW."
                ),
                remediation=(
                    "Validate and allowlist URLs before making outbound requests. "
                    "Use --ssrf-listener for confirmed SSRF detection."
                ),
                confidence="LOW",
            ))

        return findings

    async def _probe_injection(
        self,
        session: ClientSession,
        tool: ToolInfo,
        param_name: str,
        target: str,
    ) -> list[Finding]:
        """Send injection probes and check if payload is reflected verbatim."""
        findings: list[Finding] = []

        for payload in INJECTION_PROBES:
            try:
                result = await session.call_tool(tool.name, {param_name: payload})
                # Check if payload appears verbatim (unescaped) in any text response
                for content_item in result.content:
                    response_text = ""
                    if hasattr(content_item, "text"):
                        response_text = content_item.text or ""
                    if payload in response_text:
                        findings.append(Finding(
                            rule_id="MCP021",
                            severity=Severity.HIGH,
                            target=target,
                            location=f"tool:{tool.name}",
                            message=(
                                f"Tool '{tool.name}' parameter '{param_name}' reflected "
                                f"injection probe payload verbatim in response: '{payload}'. "
                                "This indicates the tool does not sanitize its inputs."
                            ),
                            remediation=(
                                "Sanitize tool inputs before including them in responses or "
                                "passing them to downstream LLM calls."
                            ),
                        ))
                        break
            except Exception:
                pass

        return findings

    async def _probe_auth(
        self,
        session: ClientSession,
        tool: ToolInfo,
        param_name: str,
        target: str,
    ) -> list[Finding]:
        """Send auth probes to auth-related parameters and check for acceptance."""
        findings: list[Finding] = []

        for probe_url in AUTH_PROBES:
            try:
                result = await session.call_tool(tool.name, {param_name: probe_url})
                # If the call succeeded without error, the server accepted the http:// URL
                if not result.isError:
                    findings.append(Finding(
                        rule_id="MCP001",
                        severity=Severity.HIGH,
                        target=target,
                        location=f"tool:{tool.name}",
                        message=(
                            f"Tool '{tool.name}' auth parameter '{param_name}' accepted "
                            f"plaintext HTTP URL '{probe_url}' without error. "
                            "The server may not enforce HTTPS for authentication endpoints."
                        ),
                        remediation=(
                            "Reject plaintext HTTP URLs for authentication-related parameters. "
                            "Enforce HTTPS for all auth/callback endpoints."
                        ),
                        confidence="LOW",
                    ))
                    break
            except Exception:
                pass

        return findings

    async def _run_probes(
        self, session: ClientSession, tools: list[ToolInfo], target: str
    ) -> list[Finding]:
        """Dispatch probes to string-typed params; apply MCP020/021 to all tools."""
        findings: list[Finding] = []

        for tool in tools:
            # Always apply description analysis (MCP020/021) regardless of destructive status
            mcp020_finding = self._check_description_mcp020(tool, target)
            if mcp020_finding:
                findings.append(mcp020_finding)

            mcp021_finding = self._check_description_mcp021(tool, target)
            if mcp021_finding:
                findings.append(mcp021_finding)

            # Skip probe dispatch for destructive tools unless allow_destructive=True
            if self._is_destructive_tool(tool.name) and not self.allow_destructive:
                continue

            string_params = self._get_string_params(tool)

            for param_name in string_params:
                # SSRF probes
                ssrf_findings = await self._probe_ssrf(session, tool, param_name, target)
                findings.extend(ssrf_findings)

                # Injection probes
                injection_findings = await self._probe_injection(
                    session, tool, param_name, target
                )
                findings.extend(injection_findings)

                # Auth probes — only for auth-related parameter names
                if self._is_auth_param(param_name):
                    auth_findings = await self._probe_auth(
                        session, tool, param_name, target
                    )
                    findings.extend(auth_findings)

        return findings

    async def _probe_with_stdio(self, target: str) -> ScanResult:
        """Connect via stdio transport, enumerate tools, run probes."""
        # Parse command string into command + args
        import shlex
        parts = shlex.split(target)
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        server_params = StdioServerParameters(command=command, args=args)

        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await asyncio.wait_for(session.initialize(), timeout=self.timeout)
                tools = await self._enumerate_tools(session)
                findings = await self._run_probes(session, tools, target)

        return ScanResult(
            findings=findings,
            scan_mode="dynamic",
            target=target,
            timestamp=datetime.now(timezone.utc),
            tool_version=_TOOL_VERSION,
        )

    async def _probe_with_http(self, target: str) -> ScanResult:
        """Connect via HTTP transport, enumerate tools, run probes."""
        async with streamable_http_client(target) as (read_stream, write_stream, _get_session_id):
            async with ClientSession(read_stream, write_stream) as session:
                await asyncio.wait_for(session.initialize(), timeout=self.timeout)
                tools = await self._enumerate_tools(session)
                findings = await self._run_probes(session, tools, target)

        return ScanResult(
            findings=findings,
            scan_mode="dynamic",
            target=target,
            timestamp=datetime.now(timezone.utc),
            tool_version=_TOOL_VERSION,
        )

    async def probe(self, target: str) -> ScanResult:
        """Connect to target (stdio command or HTTP URL), enumerate tools, run probes."""
        try:
            if target.startswith("http://") or target.startswith("https://"):
                return await self._probe_with_http(target)
            else:
                return await self._probe_with_stdio(target)
        except Exception as exc:
            # Connection failure: emit INFO finding and return gracefully
            connection_finding = Finding(
                rule_id="CONN_ERROR",
                severity=Severity.INFO,
                target=target,
                location=f"target:{target}",
                message=(
                    f"Failed to connect to MCP server at '{target}': {type(exc).__name__}: {exc}"
                ),
                remediation=(
                    "Ensure the MCP server is running and reachable. "
                    "Check the target command or URL and try again."
                ),
            )
            return ScanResult(
                findings=[connection_finding],
                scan_mode="dynamic",
                target=target,
                timestamp=datetime.now(timezone.utc),
                tool_version=_TOOL_VERSION,
            )
