"""Output formatters for mcp-scan scan results."""

from typing import Protocol

from mcp_scan.models import ScanResult
from mcp_scan.formatters.json_formatter import JsonFormatter
from mcp_scan.formatters.markdown_formatter import MarkdownFormatter
from mcp_scan.formatters.rich_formatter import RichFormatter
from mcp_scan.formatters.sarif_formatter import SarifFormatter


class Formatter(Protocol):
    """Common interface for all output formatters."""

    def format(self, result: ScanResult) -> str:
        """Render a ScanResult to a string."""
        ...


__all__ = [
    "Formatter",
    "JsonFormatter",
    "MarkdownFormatter",
    "RichFormatter",
    "SarifFormatter",
]
