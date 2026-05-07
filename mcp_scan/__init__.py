"""mcp-scan: Security scanner for Model Context Protocol (MCP) servers.

Public API:
    Scanner   - Facade for running static and/or dynamic scans
    Finding   - A single detected security issue
    ScanResult - Aggregated results from a scan run
    Severity  - Severity level enumeration
"""

from mcp_scan.models import Finding, ScanResult, Severity
from mcp_scan.scanner import Scanner

__all__ = ["Scanner", "Finding", "ScanResult", "Severity"]
