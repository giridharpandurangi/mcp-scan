"""Markdown formatter for mcp-scan results."""

from mcp_scan.models import ScanResult


class MarkdownFormatter:
    """Renders scan results as a Markdown document with summary table and per-finding sections."""

    def format(self, result: ScanResult) -> str:
        """Render a ScanResult to a Markdown string."""
        lines: list[str] = []

        lines.append("# mcp-bandit Security Report")
        lines.append("")
        lines.append(f"**Target:** `{result.target}`")
        lines.append(f"**Scan mode:** {result.scan_mode}")
        lines.append(f"**Timestamp:** {result.timestamp.isoformat()}")
        lines.append(f"**Tool version:** {result.tool_version}")
        lines.append("")

        if not result.findings:
            lines.append("## ✓ No findings")
            lines.append("")
            lines.append("Scan completed successfully — no security issues were detected.")
            lines.append("")
            return "\n".join(lines)

        lines.append(f"## Summary ({len(result.findings)} finding(s))")
        lines.append("")
        lines.append("| Rule ID | Severity | Location | Message |")
        lines.append("|---------|----------|----------|---------|")
        for finding in result.findings:
            # Escape pipe characters in message to avoid breaking the table
            message = finding.message.replace("|", "\\|")
            lines.append(
                f"| {finding.rule_id} | {finding.severity.value} | `{finding.location}` | {message} |"
            )
        lines.append("")

        lines.append("## Findings")
        lines.append("")
        for i, finding in enumerate(result.findings, start=1):
            lines.append(f"### {i}. [{finding.rule_id}] {finding.severity.value} — {finding.location}")
            lines.append("")
            lines.append(f"**Message:** {finding.message}")
            lines.append("")
            lines.append(f"**Target:** `{finding.target}`")
            lines.append("")
            lines.append(f"**Remediation:** {finding.remediation}")
            lines.append("")

        return "\n".join(lines)
