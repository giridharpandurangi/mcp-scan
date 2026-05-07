"""JSON formatter for mcp-scan results."""

from mcp_scan.models import ScanResult


class JsonFormatter:
    """Renders scan results as a JSON document conforming to the ScanResult schema."""

    def format(self, result: ScanResult) -> str:
        """Render a ScanResult to a JSON string."""
        return result.model_dump_json(indent=2)
