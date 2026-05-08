"""StaticAnalyzer: file discovery, AST parsing, and rule dispatch."""

from __future__ import annotations

import ast
import fnmatch
import importlib.metadata
from datetime import datetime, timezone
from pathlib import Path

from mcp_scan.models import Finding, ScanConfig, ScanResult, Severity
from mcp_scan.rules import Rule, discover_rules

# Type alias: local_name → (module, original_name)
AliasMap = dict[str, tuple[str, str]]


def _build_alias_map(tree: ast.AST) -> AliasMap:
    """Build a per-file alias map from import statements in the AST.

    Covers:
    - ``import httpx as h``          → ``{"h": ("httpx", "httpx")}``
    - ``from httpx import get as fetch`` → ``{"fetch": ("httpx", "get")}``
    - ``from urllib.parse import urlparse`` → ``{"urlparse": ("urllib.parse", "urlparse")}``

    Returns:
        A dict mapping local name → (module, original_name).
    """
    alias_map: AliasMap = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            # import foo, import foo as bar, import foo.bar as baz
            for alias in node.names:
                module_name = alias.name
                local_name = alias.asname if alias.asname else alias.name
                # For "import foo.bar as baz", local_name is "baz", module is "foo.bar"
                # For "import foo", local_name is "foo", module is "foo"
                alias_map[local_name] = (module_name, module_name)

        elif isinstance(node, ast.ImportFrom):
            # from module import name, from module import name as alias
            module = node.module or ""
            for alias in node.names:
                original_name = alias.name
                local_name = alias.asname if alias.asname else alias.name
                alias_map[local_name] = (module, original_name)

    return alias_map


def _get_tool_version() -> str:
    """Return the installed package version, or '0.0.0' if not found."""
    try:
        return importlib.metadata.version("mcp-bandit")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0"


class StaticAnalyzer:
    """Recursively discovers Python files, parses them, and applies detection rules.

    Rules are applied in ascending ``rule_id`` order for deterministic output.
    The alias map built from each file's import statements is stored on the
    instance (``self.alias_map``) before each rule's ``check()`` call, so that
    rules which need import resolution can access it via the analyzer reference
    passed as an optional third argument.
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        config: ScanConfig | None = None,
    ) -> None:
        """Initialize the analyzer.

        Args:
            rules: Explicit list of rules to apply.  If ``None``, all rules
                returned by :func:`~mcp_scan.rules.discover_rules` are used.
            config: Scan configuration (exclude_paths, disabled_rules, etc.).
                Defaults to a default :class:`~mcp_scan.models.ScanConfig`.
        """
        self.config: ScanConfig = config or ScanConfig()

        if rules is not None:
            # Sort caller-supplied rules by rule_id for deterministic dispatch
            self._rules: list[Rule] = sorted(rules, key=lambda r: r.rule_id)
        else:
            # Auto-discover; discover_rules() already returns sorted list
            self._rules = discover_rules()

        # Filter out disabled rules from config
        disabled = set(self.config.disabled_rules)
        if disabled:
            self._rules = [r for r in self._rules if r.rule_id not in disabled]

        # Per-file alias map; populated before each rule dispatch
        self.alias_map: AliasMap = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_path(self, path: str | Path) -> ScanResult:
        """Recursively discover .py files, parse each, apply all rules.

        For directories, files are discovered with ``sorted(root.rglob("*.py"))``
        to ensure deterministic ordering.  Glob patterns in
        ``ScanConfig.exclude_paths`` are applied to each file's path relative
        to *path* (or absolute path if *path* is a file).

        Args:
            path: A Python source file or a directory to scan recursively.

        Returns:
            A :class:`~mcp_scan.models.ScanResult` with ``scan_mode="static"``.
        """
        root = Path(path).resolve()
        all_findings: list[Finding] = []

        if root.is_file():
            py_files = [root]
        else:
            py_files = sorted(root.rglob("*.py"))

        exclude_patterns = self.config.exclude_paths

        for py_file in py_files:
            # Check exclusion patterns against the file's path string
            # Match against both the absolute path and the relative path from root
            if self._is_excluded(py_file, root, exclude_patterns):
                continue
            all_findings.extend(self.analyze_file(py_file))

        return ScanResult(
            findings=all_findings,
            scan_mode="static",
            target=str(path),
            timestamp=datetime.now(tz=timezone.utc),
            tool_version=_get_tool_version(),
        )

    def analyze_file(self, path: str | Path) -> list[Finding]:
        """Parse a single .py file and apply all rules.

        Builds a per-file alias map from import statements before dispatching
        rules.  If the file cannot be parsed (``SyntaxError``), a single
        ``Finding`` with ``severity=INFO`` and ``rule_id="PARSE_ERROR"`` is
        returned and processing continues.

        Args:
            path: Path to a Python source file.

        Returns:
            A list of :class:`~mcp_scan.models.Finding` objects (may be empty).
        """
        file_path = Path(path)
        source_path_str = str(file_path)

        # Read source
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return [
                Finding(
                    rule_id="PARSE_ERROR",
                    severity=Severity.INFO,
                    target=source_path_str,
                    location=source_path_str,
                    message=f"Could not read file: {exc}",
                    remediation="Ensure the file is readable.",
                )
            ]

        # Parse AST
        try:
            tree = ast.parse(source, filename=source_path_str)
        except SyntaxError as exc:
            return [
                Finding(
                    rule_id="PARSE_ERROR",
                    severity=Severity.INFO,
                    target=source_path_str,
                    location=f"{source_path_str}:{exc.lineno or 0}",
                    message=f"Syntax error: {exc.msg}",
                    remediation="Fix the syntax error in the file.",
                )
            ]

        # Build alias map for this file
        self.alias_map = _build_alias_map(tree)

        # Dispatch rules in ascending rule_id order (already sorted in __init__)
        findings: list[Finding] = []
        for rule in self._rules:
            try:
                rule_findings = rule.check(tree, source_path_str)
                findings.extend(rule_findings)
            except Exception as exc:  # noqa: BLE001
                # A rule crash must not abort the entire scan
                findings.append(
                    Finding(
                        rule_id="RULE_ERROR",
                        severity=Severity.INFO,
                        target=source_path_str,
                        location=source_path_str,
                        message=f"Rule {rule.rule_id} raised an exception: {exc}",
                        remediation="Report this as a bug in mcp-scan.",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_excluded(
        file_path: Path,
        root: Path,
        patterns: list[str],
    ) -> bool:
        """Return True if *file_path* matches any of the exclusion *patterns*.

        Patterns are matched against:
        1. The path relative to *root* (as a POSIX string).
        2. The absolute path string.
        3. Just the filename.

        Uses :func:`fnmatch.fnmatch` for glob-style matching.
        """
        if not patterns:
            return False

        try:
            rel_path = file_path.relative_to(root)
            rel_str = rel_path.as_posix()
        except ValueError:
            rel_str = str(file_path)

        abs_str = str(file_path)
        name_str = file_path.name

        for pattern in patterns:
            if (
                fnmatch.fnmatch(rel_str, pattern)
                or fnmatch.fnmatch(abs_str, pattern)
                or fnmatch.fnmatch(name_str, pattern)
            ):
                return True
        return False
