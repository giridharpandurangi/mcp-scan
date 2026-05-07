"""Scanner facade: orchestrates static and dynamic analysis and merges results."""

from __future__ import annotations

import importlib.metadata
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from mcp_scan.models import ScanConfig, ScanResult
from mcp_scan.static.analyzer import StaticAnalyzer

if TYPE_CHECKING:
    from mcp_scan.dynamic.prober import DynamicProber


def _get_tool_version() -> str:
    """Return the installed package version, or '0.0.0' if not found."""
    try:
        return importlib.metadata.version("mcp-scan")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0"


def _apply_severity_filter(result: ScanResult, config: ScanConfig) -> ScanResult:
    """Return a new ScanResult with findings below min_severity removed."""
    if config.min_severity is None:
        return result
    filtered = [f for f in result.findings if f.severity >= config.min_severity]
    if len(filtered) == len(result.findings):
        return result
    return result.model_copy(update={"findings": filtered})


class Scanner:
    """Facade for running static and/or dynamic scans against MCP servers.

    Applies :class:`~mcp_scan.models.ScanConfig` filters (disabled rules,
    min severity, exclude paths) before returning results.
    """

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()

    def scan_static(self, path: str | Path) -> ScanResult:
        """Run static analysis on a Python source file or directory.

        Delegates to :class:`~mcp_scan.static.analyzer.StaticAnalyzer` with
        the current :attr:`config` (which carries ``disabled_rules`` and
        ``exclude_paths``).  The ``min_severity`` filter is applied after
        analysis so that the analyzer itself still runs all non-disabled rules.

        Args:
            path: Path to a Python source file or directory.

        Returns:
            A :class:`~mcp_scan.models.ScanResult` with ``scan_mode="static"``.
        """
        analyzer = StaticAnalyzer(config=self.config)
        result = analyzer.analyze_path(path)
        return _apply_severity_filter(result, self.config)

    async def scan_dynamic(self, target: str) -> ScanResult:
        """Run dynamic probing against a running MCP server.

        Delegates to :class:`~mcp_scan.dynamic.prober.DynamicProber`.
        The ``min_severity`` filter is applied after probing.

        Args:
            target: A stdio command string or an HTTP/HTTPS URL.

        Returns:
            A :class:`~mcp_scan.models.ScanResult` with ``scan_mode="dynamic"``.
        """
        from mcp_scan.dynamic.prober import DynamicProber  # lazy import to avoid MCP client init at module load

        prober = DynamicProber()
        result = await prober.probe(target)
        return _apply_severity_filter(result, self.config)

    async def scan_all(self, path: str | Path, target: str) -> ScanResult:
        """Run both static and dynamic analysis and merge findings.

        Runs :meth:`scan_static` and :meth:`scan_dynamic` independently, then
        merges their findings into a single :class:`~mcp_scan.models.ScanResult`
        with ``scan_mode="all"``.  The ``min_severity`` filter is applied to
        the merged result.

        Args:
            path: Path to a Python source file or directory (for static analysis).
            target: A stdio command string or HTTP/HTTPS URL (for dynamic analysis).

        Returns:
            A :class:`~mcp_scan.models.ScanResult` with ``scan_mode="all"``.
        """
        from mcp_scan.dynamic.prober import DynamicProber  # lazy import to avoid MCP client init at module load

        # Run static analysis (synchronous)
        analyzer = StaticAnalyzer(config=self.config)
        static_result = analyzer.analyze_path(path)

        # Run dynamic analysis (async)
        prober = DynamicProber()
        dynamic_result = await prober.probe(target)

        # Merge findings from both analyzers
        merged_findings = list(static_result.findings) + list(dynamic_result.findings)

        merged = ScanResult(
            findings=merged_findings,
            scan_mode="all",
            target=str(path),
            timestamp=datetime.now(timezone.utc),
            tool_version=_get_tool_version(),
        )

        return _apply_severity_filter(merged, self.config)
