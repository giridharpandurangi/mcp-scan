"""Rich terminal formatter for mcp-scan results."""

from io import StringIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from mcp_scan.models import Severity, ScanResult

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "dark_orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "white",
}


class RichFormatter:
    """Renders scan results as a rich terminal table with severity color coding."""

    def format(self, result: ScanResult) -> str:
        """Render a ScanResult to a rich-formatted string."""
        # Use a fixed width and force Unicode box-drawing so output is deterministic
        # regardless of terminal size or platform (avoids ASCII fallback on Windows).
        console = Console(record=True, highlight=False, width=100, force_terminal=True, legacy_windows=False)

        if not result.findings:
            console.print("[green]✓ No findings — scan completed successfully.[/green]")
            return console.export_text()

        table = Table(
            title=f"mcp-bandit results — {result.target}",
            show_header=True,
            header_style="bold",
        )
        table.add_column("Rule ID", style="bold", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Location")
        table.add_column("Message")

        for finding in result.findings:
            color = _SEVERITY_COLORS.get(finding.severity, "white")
            severity_text = Text(finding.severity.value, style=color)
            table.add_row(
                finding.rule_id,
                severity_text,
                finding.location,
                finding.message,
            )

        console.print(table)
        return console.export_text()
