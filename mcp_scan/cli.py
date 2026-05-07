"""CLI entry point for mcp-scan using typer.

Subcommands
-----------
static   Run static analysis on a Python source file or directory.
dynamic  Run dynamic probing against a running MCP server.
all      Run both static and dynamic analysis and merge findings.
rules    List all registered detection rules.

Exit codes
----------
0  Scan completed, no findings at or above HIGH severity.
1  Scan completed, one or more findings at or above HIGH severity.
2  Scan failed due to configuration or runtime error.
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer

from mcp_scan.config import load_config
from mcp_scan.models import ScanConfig, ScanResult, Severity
from mcp_scan.rules import discover_rules
from mcp_scan.scanner import Scanner

app = typer.Typer(
    name="mcp-scan",
    help="Security scanner for Model Context Protocol (MCP) servers.",
    no_args_is_help=True,
    add_completion=False,
)

# ---------------------------------------------------------------------------
# Type aliases for shared CLI options
# ---------------------------------------------------------------------------

_FormatOption = Annotated[
    str,
    typer.Option(
        "--format", "-f",
        help="Output format: rich, json, sarif, or markdown.",
        show_default=True,
    ),
]
_OutputOption = Annotated[
    Optional[Path],
    typer.Option(
        "--output", "-o",
        help="Write output to this file instead of stdout.",
    ),
]
_SeverityOption = Annotated[
    Optional[str],
    typer.Option(
        "--severity", "-s",
        help="Minimum severity to include: CRITICAL, HIGH, MEDIUM, LOW, INFO.",
    ),
]
_RuleOption = Annotated[
    Optional[str],
    typer.Option(
        "--rule", "-r",
        help="Run only this rule ID (e.g. MCP001). All others are suppressed.",
    ),
]
_ConfigOption = Annotated[
    Optional[Path],
    typer.Option(
        "--config", "-c",
        help="Path to a TOML or JSON configuration file.",
    ),
]

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_VALID_FORMATS = {"rich", "json", "sarif", "markdown"}
_VALID_SEVERITIES = {s.value for s in Severity}


def _get_formatter(fmt: str):
    """Return the formatter instance for *fmt*. Raises typer.Exit(2) on bad value."""
    from mcp_scan.formatters import (
        JsonFormatter,
        MarkdownFormatter,
        RichFormatter,
        SarifFormatter,
    )

    mapping = {
        "rich": RichFormatter,
        "json": JsonFormatter,
        "sarif": SarifFormatter,
        "markdown": MarkdownFormatter,
    }
    if fmt not in mapping:
        typer.echo(
            f"Error: invalid format '{fmt}'. Choose from: {', '.join(sorted(mapping))}",
            err=True,
        )
        raise typer.Exit(2)
    return mapping[fmt]()


def _parse_severity(value: Optional[str]) -> Optional[Severity]:
    """Parse a severity string to a Severity enum. Raises typer.Exit(2) on bad value."""
    if value is None:
        return None
    upper = value.upper()
    try:
        return Severity(upper)
    except ValueError:
        typer.echo(
            f"Error: invalid severity '{value}'. "
            f"Choose from: {', '.join(s.value for s in Severity)}",
            err=True,
        )
        raise typer.Exit(2)


def _load_config_file(config_path: Optional[Path]) -> ScanConfig:
    """Load ScanConfig from *config_path* if provided, else return defaults."""
    if config_path is None:
        return ScanConfig()
    try:
        return load_config(config_path)
    except FileNotFoundError:
        typer.echo(f"Error: config file not found: {config_path}", err=True)
        raise typer.Exit(2)
    except Exception as exc:
        typer.echo(f"Error: failed to load config file: {exc}", err=True)
        raise typer.Exit(2)


def _build_config(
    config_path: Optional[Path],
    severity: Optional[str],
    rule: Optional[str],
) -> ScanConfig:
    """Build a ScanConfig from config file + CLI flag overrides."""
    cfg = _load_config_file(config_path)

    # CLI --severity overrides config file min_severity
    parsed_severity = _parse_severity(severity)
    if parsed_severity is not None:
        cfg = cfg.model_copy(update={"min_severity": parsed_severity})

    # CLI --rule disables all rules except the specified one
    if rule is not None:
        all_rules = discover_rules()
        all_ids = {r.rule_id for r in all_rules}
        if rule not in all_ids:
            typer.echo(
                f"Error: unknown rule '{rule}'. "
                f"Run 'mcp-scan rules' to see available rules.",
                err=True,
            )
            raise typer.Exit(2)
        disabled = [r_id for r_id in all_ids if r_id != rule]
        cfg = cfg.model_copy(update={"disabled_rules": disabled})

    return cfg


def _write_output(text: str, output: Optional[Path]) -> None:
    """Write *text* to *output* file or stdout."""
    if output is None:
        typer.echo(text, nl=False)
        return
    try:
        output.write_text(text, encoding="utf-8")
    except OSError as exc:
        typer.echo(f"Error: cannot write to '{output}': {exc}", err=True)
        raise typer.Exit(2)


def _exit_for_result(result: ScanResult) -> None:
    """Exit with code 1 if any finding is HIGH or above, else 0."""
    if any(f.severity >= Severity.HIGH for f in result.findings):
        raise typer.Exit(1)
    raise typer.Exit(0)


# ---------------------------------------------------------------------------
# `static` subcommand
# ---------------------------------------------------------------------------


@app.command()
def static(
    path: Annotated[
        Path,
        typer.Option("--path", "-p", help="Python source file or directory to scan."),
    ] = Path("."),
    format: _FormatOption = "rich",
    output: _OutputOption = None,
    severity: _SeverityOption = None,
    rule: _RuleOption = None,
    config: _ConfigOption = None,
) -> None:
    """Run static analysis on a Python source file or directory."""
    cfg = _build_config(config, severity, rule)
    scanner = Scanner(config=cfg)

    try:
        result = scanner.scan_static(path)
    except Exception as exc:
        typer.echo(f"Error: static scan failed: {exc}", err=True)
        raise typer.Exit(2)

    formatter = _get_formatter(format)
    _write_output(formatter.format(result), output)
    _exit_for_result(result)


# ---------------------------------------------------------------------------
# `dynamic` subcommand
# ---------------------------------------------------------------------------


@app.command()
def dynamic(
    target: Annotated[
        str,
        typer.Option("--target", "-t", help="stdio command or HTTP/HTTPS URL of the MCP server."),
    ],
    format: _FormatOption = "rich",
    output: _OutputOption = None,
    severity: _SeverityOption = None,
    config: _ConfigOption = None,
    allow_destructive: Annotated[
        bool,
        typer.Option(
            "--allow-destructive",
            help="Send probes to tools with destructive names (delete*, drop*, etc.).",
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip the --allow-destructive confirmation prompt."),
    ] = False,
    ssrf_listener: Annotated[
        Optional[str],
        typer.Option(
            "--ssrf-listener",
            help="Address of a controlled HTTP listener for confirmed SSRF detection.",
        ),
    ] = None,
) -> None:
    """Run dynamic probing against a running MCP server."""
    # Confirmation prompt for --allow-destructive
    if allow_destructive and not yes:
        typer.echo(
            "WARNING: --allow-destructive is enabled. mcp-scan will send probe payloads\n"
            "to tools whose names suggest destructive operations (delete*, drop*, write*, etc.).\n"
            "This may cause unintended side effects on the target server.",
            err=True,
        )
        confirmed = typer.confirm("Continue?", default=False)
        if not confirmed:
            raise typer.Exit(0)

    cfg = _build_config(config, severity, None)
    scanner = Scanner(config=cfg)

    try:
        result = asyncio.run(scanner.scan_dynamic(target))
    except Exception as exc:
        typer.echo(f"Error: dynamic scan failed: {exc}", err=True)
        raise typer.Exit(2)

    formatter = _get_formatter(format)
    _write_output(formatter.format(result), output)
    _exit_for_result(result)


# ---------------------------------------------------------------------------
# `all` subcommand
# ---------------------------------------------------------------------------


@app.command(name="all")
def scan_all(
    path: Annotated[
        Path,
        typer.Option("--path", "-p", help="Python source file or directory to scan."),
    ] = Path("."),
    target: Annotated[
        str,
        typer.Option("--target", "-t", help="stdio command or HTTP/HTTPS URL of the MCP server."),
    ] = "",
    format: _FormatOption = "rich",
    output: _OutputOption = None,
    severity: _SeverityOption = None,
    rule: _RuleOption = None,
    config: _ConfigOption = None,
    allow_destructive: Annotated[
        bool,
        typer.Option(
            "--allow-destructive",
            help="Send probes to tools with destructive names.",
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip the --allow-destructive confirmation prompt."),
    ] = False,
) -> None:
    """Run both static and dynamic analysis and merge findings."""
    if not target:
        typer.echo("Error: --target is required for the 'all' subcommand.", err=True)
        raise typer.Exit(2)

    if allow_destructive and not yes:
        typer.echo(
            "WARNING: --allow-destructive is enabled. mcp-scan will send probe payloads\n"
            "to tools whose names suggest destructive operations.",
            err=True,
        )
        confirmed = typer.confirm("Continue?", default=False)
        if not confirmed:
            raise typer.Exit(0)

    cfg = _build_config(config, severity, rule)
    scanner = Scanner(config=cfg)

    try:
        result = asyncio.run(scanner.scan_all(path, target))
    except Exception as exc:
        typer.echo(f"Error: scan failed: {exc}", err=True)
        raise typer.Exit(2)

    formatter = _get_formatter(format)
    _write_output(formatter.format(result), output)
    _exit_for_result(result)


# ---------------------------------------------------------------------------
# `rules` subcommand
# ---------------------------------------------------------------------------


@app.command()
def rules() -> None:
    """List all registered detection rules with ID, severity, description, and CWE."""
    all_rules = discover_rules()

    if not all_rules:
        typer.echo("No rules registered.")
        return

    from rich.console import Console
    from rich.table import Table

    console = Console(highlight=False, width=120)
    table = Table(title="mcp-scan Detection Rules", show_header=True, header_style="bold")
    table.add_column("Rule ID", style="bold", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("CWE", no_wrap=True)
    table.add_column("Description")

    for rule in all_rules:
        table.add_row(
            rule.rule_id,
            rule.severity.value,
            getattr(rule, "cwe", "—"),
            getattr(rule, "description", ""),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# `--version` flag (callback on the root app)
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    if value:
        try:
            version = importlib.metadata.version("mcp-scan")
        except importlib.metadata.PackageNotFoundError:
            version = "0.0.0"
        typer.echo(f"mcp-scan {version}")
        raise typer.Exit(0)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Print the tool version and exit.",
        ),
    ] = False,
) -> None:
    """mcp-scan — Security scanner for Model Context Protocol (MCP) servers."""


if __name__ == "__main__":
    app()
