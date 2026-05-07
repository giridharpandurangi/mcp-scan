"""Unit tests for StaticAnalyzer.

Task 4.1 — Requirements 2.2, 2.3, 2.4, 2.8

Tests cover:
- Recursive .py file discovery from a directory
- Parse error produces INFO finding and continues
- Alias map: ``from urllib.parse import urlparse`` → ``{"urlparse": ("urllib.parse", "urlparse")}``
  (dedicated regression test)
- Alias map: ``from httpx import get as fetch`` and ``import httpx as h``
- Rule dispatch order is stable (sorted by rule_id)
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from mcp_scan.models import Finding, ScanConfig, Severity
from mcp_scan.rules import Rule
from mcp_scan.static.analyzer import StaticAnalyzer, _build_alias_map
from tests.conftest import make_stub_rule_class


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_py(tmp_path: Path, rel_path: str, source: str) -> Path:
    """Write *source* to *tmp_path / rel_path*, creating parent dirs as needed."""
    target = tmp_path / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(textwrap.dedent(source), encoding="utf-8")
    return target


def _make_recording_rule(rule_id: str) -> tuple[Rule, list[tuple[str, str]]]:
    """Return a (rule_instance, calls_log) pair.

    The rule records every ``(source_path, rule_id)`` call made to ``check()``.
    """
    calls: list[tuple[str, str]] = []

    class RecordingRule(Rule):
        def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
            calls.append((source_path, self.rule_id))
            return []

    RecordingRule.rule_id = rule_id  # type: ignore[attr-defined]
    RecordingRule.severity = Severity.INFO  # type: ignore[attr-defined]
    RecordingRule.cwe = "CWE-000"  # type: ignore[attr-defined]
    RecordingRule.description = f"Recording rule {rule_id}"  # type: ignore[attr-defined]
    RecordingRule.remediation = "N/A"  # type: ignore[attr-defined]

    return RecordingRule(), calls


# ---------------------------------------------------------------------------
# File discovery (Requirement 2.2)
# ---------------------------------------------------------------------------


class TestFileDiscovery:
    def test_single_file_is_analyzed(self, tmp_path):
        """Passing a single .py file path analyzes exactly that file."""
        f = _write_py(tmp_path, "server.py", "x = 1\n")
        analyzer = StaticAnalyzer(rules=[])
        result = analyzer.analyze_path(f)
        assert result.scan_mode == "static"
        assert result.target == str(f)

    def test_directory_discovers_all_py_files(self, tmp_path):
        """All .py files in a directory tree are discovered and analyzed."""
        rule, calls = _make_recording_rule("MCP_REC")
        _write_py(tmp_path, "a.py", "x = 1\n")
        _write_py(tmp_path, "sub/b.py", "y = 2\n")
        _write_py(tmp_path, "sub/deep/c.py", "z = 3\n")

        analyzer = StaticAnalyzer(rules=[rule])
        analyzer.analyze_path(tmp_path)

        analyzed_paths = {path for path, _ in calls}
        assert any("a.py" in p for p in analyzed_paths)
        assert any("b.py" in p for p in analyzed_paths)
        assert any("c.py" in p for p in analyzed_paths)

    def test_non_py_files_are_ignored(self, tmp_path):
        """Non-.py files in the directory are not analyzed."""
        rule, calls = _make_recording_rule("MCP_REC")
        _write_py(tmp_path, "server.py", "x = 1\n")
        (tmp_path / "README.md").write_text("# readme", encoding="utf-8")
        (tmp_path / "config.toml").write_text("[tool]\n", encoding="utf-8")

        analyzer = StaticAnalyzer(rules=[rule])
        analyzer.analyze_path(tmp_path)

        analyzed_paths = {path for path, _ in calls}
        assert all(p.endswith(".py") for p in analyzed_paths)
        assert len(analyzed_paths) == 1

    def test_empty_directory_produces_no_findings(self, tmp_path):
        """An empty directory produces a ScanResult with zero findings."""
        analyzer = StaticAnalyzer(rules=[])
        result = analyzer.analyze_path(tmp_path)
        assert result.findings == []

    def test_discovery_order_is_deterministic(self, tmp_path):
        """Files are processed in sorted order (sorted rglob) for determinism."""
        rule, calls = _make_recording_rule("MCP_REC")
        _write_py(tmp_path, "z_last.py", "z = 1\n")
        _write_py(tmp_path, "a_first.py", "a = 1\n")
        _write_py(tmp_path, "m_middle.py", "m = 1\n")

        analyzer = StaticAnalyzer(rules=[rule])
        analyzer.analyze_path(tmp_path)

        analyzed_paths = [path for path, _ in calls]
        assert analyzed_paths == sorted(analyzed_paths), (
            f"Files were not processed in sorted order: {analyzed_paths}"
        )

    def test_exclude_paths_skips_matching_files(self, tmp_path):
        """Files matching exclude_paths glob patterns are not analyzed."""
        rule, calls = _make_recording_rule("MCP_REC")
        _write_py(tmp_path, "server.py", "x = 1\n")
        _write_py(tmp_path, "tests/test_server.py", "y = 2\n")

        config = ScanConfig(exclude_paths=["tests/**"])
        analyzer = StaticAnalyzer(rules=[rule], config=config)
        analyzer.analyze_path(tmp_path)

        analyzed_paths = {path for path, _ in calls}
        assert any("server.py" in p for p in analyzed_paths)
        assert not any("test_server.py" in p for p in analyzed_paths)

    def test_scan_result_has_correct_scan_mode(self, tmp_path):
        """ScanResult from analyze_path always has scan_mode='static'."""
        _write_py(tmp_path, "x.py", "pass\n")
        analyzer = StaticAnalyzer(rules=[])
        result = analyzer.analyze_path(tmp_path)
        assert result.scan_mode == "static"


# ---------------------------------------------------------------------------
# Parse error handling (Requirement 2.3)
# ---------------------------------------------------------------------------


class TestParseErrorHandling:
    def test_syntax_error_produces_info_finding(self, tmp_path):
        """A file with a syntax error produces a single INFO/PARSE_ERROR finding."""
        bad_file = _write_py(tmp_path, "broken.py", "def foo(\n")  # unclosed paren

        analyzer = StaticAnalyzer(rules=[])
        findings = analyzer.analyze_file(bad_file)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "PARSE_ERROR"
        assert finding.severity == Severity.INFO

    def test_syntax_error_finding_contains_file_path(self, tmp_path):
        """The PARSE_ERROR finding's target references the broken file."""
        bad_file = _write_py(tmp_path, "broken.py", "def foo(\n")

        analyzer = StaticAnalyzer(rules=[])
        findings = analyzer.analyze_file(bad_file)

        assert findings[0].target == str(bad_file)

    def test_parse_error_does_not_stop_other_files(self, tmp_path):
        """After a parse error, the analyzer continues processing remaining files."""
        rule, calls = _make_recording_rule("MCP_REC")
        _write_py(tmp_path, "a_broken.py", "def foo(\n")  # syntax error
        _write_py(tmp_path, "b_valid.py", "x = 1\n")

        analyzer = StaticAnalyzer(rules=[rule])
        result = analyzer.analyze_path(tmp_path)

        # The valid file must have been analyzed (rule called on it)
        analyzed_paths = {path for path, _ in calls}
        assert any("b_valid.py" in p for p in analyzed_paths)

        # The broken file must have produced a PARSE_ERROR finding
        parse_errors = [f for f in result.findings if f.rule_id == "PARSE_ERROR"]
        assert len(parse_errors) == 1

    def test_parse_error_finding_has_message(self, tmp_path):
        """The PARSE_ERROR finding includes a non-empty message describing the error."""
        bad_file = _write_py(tmp_path, "broken.py", "def foo(\n")

        analyzer = StaticAnalyzer(rules=[])
        findings = analyzer.analyze_file(bad_file)

        assert findings[0].message  # non-empty

    def test_valid_file_produces_no_parse_error(self, tmp_path):
        """A syntactically valid file produces no PARSE_ERROR finding."""
        good_file = _write_py(tmp_path, "good.py", "x = 1\n")

        analyzer = StaticAnalyzer(rules=[])
        findings = analyzer.analyze_file(good_file)

        assert not any(f.rule_id == "PARSE_ERROR" for f in findings)


# ---------------------------------------------------------------------------
# Alias map — dedicated regression tests (Requirement 2.4)
# ---------------------------------------------------------------------------


class TestAliasMap:
    """Regression tests for _build_alias_map.

    The ``from urllib.parse import urlparse`` case is the most common way
    developers import urlparse and must be covered explicitly to prevent
    regression (per design doc).
    """

    def test_urlparse_from_import_regression(self):
        """REGRESSION: ``from urllib.parse import urlparse`` must produce
        ``{"urlparse": ("urllib.parse", "urlparse")}``.

        This is the most common import form and must not be missed.
        """
        source = "from urllib.parse import urlparse"
        tree = ast.parse(source)
        alias_map = _build_alias_map(tree)

        assert "urlparse" in alias_map, (
            "urlparse not found in alias map — regression in from-import handling"
        )
        assert alias_map["urlparse"] == ("urllib.parse", "urlparse"), (
            f"Expected ('urllib.parse', 'urlparse'), got {alias_map['urlparse']}"
        )

    def test_urlparse_from_import_with_alias(self):
        """``from urllib.parse import urlparse as up`` → ``{"up": ("urllib.parse", "urlparse")}``."""
        source = "from urllib.parse import urlparse as up"
        tree = ast.parse(source)
        alias_map = _build_alias_map(tree)

        assert "up" in alias_map
        assert alias_map["up"] == ("urllib.parse", "urlparse")

    def test_httpx_from_import_with_alias(self):
        """``from httpx import get as fetch`` → ``{"fetch": ("httpx", "get")}``."""
        source = "from httpx import get as fetch"
        tree = ast.parse(source)
        alias_map = _build_alias_map(tree)

        assert "fetch" in alias_map
        assert alias_map["fetch"] == ("httpx", "get")

    def test_httpx_module_alias(self):
        """``import httpx as h`` → ``{"h": ("httpx", "httpx")}``."""
        source = "import httpx as h"
        tree = ast.parse(source)
        alias_map = _build_alias_map(tree)

        assert "h" in alias_map
        assert alias_map["h"] == ("httpx", "httpx")

    def test_plain_import_no_alias(self):
        """``import httpx`` → ``{"httpx": ("httpx", "httpx")}``."""
        source = "import httpx"
        tree = ast.parse(source)
        alias_map = _build_alias_map(tree)

        assert "httpx" in alias_map
        assert alias_map["httpx"] == ("httpx", "httpx")

    def test_multiple_imports_in_one_statement(self):
        """``from httpx import get, post`` → both names mapped to httpx."""
        source = "from httpx import get, post"
        tree = ast.parse(source)
        alias_map = _build_alias_map(tree)

        assert alias_map.get("get") == ("httpx", "get")
        assert alias_map.get("post") == ("httpx", "post")

    def test_mixed_imports_all_captured(self):
        """Multiple import styles in one file are all captured."""
        source = textwrap.dedent("""\
            import httpx as h
            from httpx import get as fetch
            from urllib.parse import urlparse
            import requests
        """)
        tree = ast.parse(source)
        alias_map = _build_alias_map(tree)

        assert alias_map.get("h") == ("httpx", "httpx")
        assert alias_map.get("fetch") == ("httpx", "get")
        assert alias_map.get("urlparse") == ("urllib.parse", "urlparse")
        assert alias_map.get("requests") == ("requests", "requests")

    def test_empty_file_produces_empty_alias_map(self):
        """A file with no imports produces an empty alias map."""
        tree = ast.parse("x = 1\n")
        alias_map = _build_alias_map(tree)
        assert alias_map == {}

    def test_alias_map_stored_on_analyzer_after_analyze_file(self, tmp_path):
        """After analyze_file(), self.alias_map reflects the analyzed file's imports."""
        source = textwrap.dedent("""\
            from urllib.parse import urlparse
            x = 1
        """)
        f = _write_py(tmp_path, "server.py", source)

        analyzer = StaticAnalyzer(rules=[])
        analyzer.analyze_file(f)

        assert "urlparse" in analyzer.alias_map
        assert analyzer.alias_map["urlparse"] == ("urllib.parse", "urlparse")


# ---------------------------------------------------------------------------
# Rule dispatch order (Requirement 2.8)
# ---------------------------------------------------------------------------


class TestRuleDispatchOrder:
    def test_rules_applied_in_ascending_rule_id_order(self, tmp_path):
        """Rules are dispatched in ascending rule_id order regardless of
        the order they are passed to StaticAnalyzer.__init__.
        """
        dispatch_order: list[str] = []

        def _recording_rule(rule_id: str) -> Rule:
            class R(Rule):
                def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
                    dispatch_order.append(self.rule_id)
                    return []

            R.rule_id = rule_id  # type: ignore[attr-defined]
            R.severity = Severity.INFO  # type: ignore[attr-defined]
            R.cwe = "CWE-000"  # type: ignore[attr-defined]
            R.description = f"Rule {rule_id}"  # type: ignore[attr-defined]
            R.remediation = "N/A"  # type: ignore[attr-defined]
            return R()

        # Pass rules in reverse order — analyzer must sort them
        rules = [
            _recording_rule("MCP_Z"),
            _recording_rule("MCP_M"),
            _recording_rule("MCP_A"),
        ]

        f = _write_py(tmp_path, "server.py", "x = 1\n")
        analyzer = StaticAnalyzer(rules=rules)
        analyzer.analyze_file(f)

        assert dispatch_order == ["MCP_A", "MCP_M", "MCP_Z"], (
            f"Rules were not dispatched in sorted order: {dispatch_order}"
        )

    def test_rule_dispatch_order_is_stable_across_two_runs(self, tmp_path):
        """Running the analyzer twice on the same file produces the same
        rule dispatch order (determinism requirement).
        """
        dispatch_orders: list[list[str]] = []

        def _recording_rule(rule_id: str) -> Rule:
            class R(Rule):
                def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
                    return []

            R.rule_id = rule_id  # type: ignore[attr-defined]
            R.severity = Severity.INFO  # type: ignore[attr-defined]
            R.cwe = "CWE-000"  # type: ignore[attr-defined]
            R.description = f"Rule {rule_id}"  # type: ignore[attr-defined]
            R.remediation = "N/A"  # type: ignore[attr-defined]
            return R()

        rules = [_recording_rule(rid) for rid in ("MCP_C", "MCP_A", "MCP_B")]
        f = _write_py(tmp_path, "server.py", "x = 1\n")

        for _ in range(2):
            order: list[str] = []

            class TrackingRule(Rule):
                def __init__(self, inner: Rule) -> None:
                    self._inner = inner
                    self.rule_id = inner.rule_id  # type: ignore[attr-defined]
                    self.severity = inner.severity  # type: ignore[attr-defined]
                    self.cwe = inner.cwe  # type: ignore[attr-defined]
                    self.description = inner.description  # type: ignore[attr-defined]
                    self.remediation = inner.remediation  # type: ignore[attr-defined]

                def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
                    order.append(self.rule_id)
                    return []

            tracking_rules = [TrackingRule(r) for r in rules]
            analyzer = StaticAnalyzer(rules=tracking_rules)
            analyzer.analyze_file(f)
            dispatch_orders.append(order)

        assert dispatch_orders[0] == dispatch_orders[1], (
            "Rule dispatch order differed between two runs — not deterministic"
        )

    def test_disabled_rules_are_not_dispatched(self, tmp_path):
        """Rules listed in ScanConfig.disabled_rules are not called."""
        dispatched: list[str] = []

        def _recording_rule(rule_id: str) -> Rule:
            class R(Rule):
                def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
                    dispatched.append(self.rule_id)
                    return []

            R.rule_id = rule_id  # type: ignore[attr-defined]
            R.severity = Severity.INFO  # type: ignore[attr-defined]
            R.cwe = "CWE-000"  # type: ignore[attr-defined]
            R.description = f"Rule {rule_id}"  # type: ignore[attr-defined]
            R.remediation = "N/A"  # type: ignore[attr-defined]
            return R()

        rules = [_recording_rule("MCP_KEEP"), _recording_rule("MCP_SKIP")]
        config = ScanConfig(disabled_rules=["MCP_SKIP"])
        f = _write_py(tmp_path, "server.py", "x = 1\n")

        analyzer = StaticAnalyzer(rules=rules, config=config)
        analyzer.analyze_file(f)

        assert "MCP_KEEP" in dispatched
        assert "MCP_SKIP" not in dispatched

    def test_rule_exception_does_not_abort_scan(self, tmp_path):
        """If a rule raises an exception, a RULE_ERROR finding is emitted and
        the remaining rules still run.
        """
        class CrashingRule(Rule):
            rule_id = "MCP_CRASH"  # type: ignore[assignment]
            severity = Severity.INFO  # type: ignore[assignment]
            cwe = "CWE-000"  # type: ignore[assignment]
            description = "Crashes on check"  # type: ignore[assignment]
            remediation = "N/A"  # type: ignore[assignment]

            def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
                raise RuntimeError("intentional crash")

        ran: list[str] = []

        class AfterRule(Rule):
            rule_id = "MCP_AFTER"  # type: ignore[assignment]
            severity = Severity.INFO  # type: ignore[assignment]
            cwe = "CWE-000"  # type: ignore[assignment]
            description = "Runs after crash"  # type: ignore[assignment]
            remediation = "N/A"  # type: ignore[assignment]

            def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
                ran.append(self.rule_id)
                return []

        f = _write_py(tmp_path, "server.py", "x = 1\n")
        analyzer = StaticAnalyzer(rules=[CrashingRule(), AfterRule()])
        findings = analyzer.analyze_file(f)

        # RULE_ERROR finding must be present
        rule_errors = [f for f in findings if f.rule_id == "RULE_ERROR"]
        assert len(rule_errors) == 1

        # The rule after the crash must still have run
        assert "MCP_AFTER" in ran


# ---------------------------------------------------------------------------
# Determinism (Requirement 2.8)
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_file_analyzed_twice_produces_identical_findings(self, tmp_path):
        """Analyzing the same file twice with the same rules produces identical
        Finding lists — same rule IDs, severities, locations, and messages.
        """
        source = textwrap.dedent("""\
            import httpx

            @mcp.tool()
            def fetch_data(url):
                return httpx.get(url)
        """)
        f = _write_py(tmp_path, "server.py", source)

        # Use the real auto-discovered rules for a realistic determinism check
        analyzer = StaticAnalyzer()
        findings_1 = analyzer.analyze_file(f)
        findings_2 = analyzer.analyze_file(f)

        assert findings_1 == findings_2, (
            "analyze_file() produced different results on two runs — not deterministic"
        )

    def test_analyze_path_twice_produces_identical_scan_results(self, tmp_path):
        """analyze_path() on the same directory twice produces identical findings."""
        _write_py(tmp_path, "a.py", "x = 1\n")
        _write_py(tmp_path, "b.py", "y = 2\n")

        analyzer = StaticAnalyzer(rules=[])
        result_1 = analyzer.analyze_path(tmp_path)
        result_2 = analyzer.analyze_path(tmp_path)

        assert result_1.findings == result_2.findings


# ---------------------------------------------------------------------------
# OSError on file read (lines 163–164)
# ---------------------------------------------------------------------------


class TestOSErrorOnRead:
    """Lines 163–164: analyze_file() catches OSError from read_text() and
    returns a PARSE_ERROR finding instead of crashing.
    """

    def test_unreadable_file_produces_parse_error_finding(self, tmp_path, monkeypatch):
        """When read_text() raises OSError, a PARSE_ERROR/INFO finding is returned."""
        f = _write_py(tmp_path, "locked.py", "x = 1\n")

        # Monkeypatch Path.read_text to raise OSError for this specific file
        original_read_text = Path.read_text

        def patched_read_text(self, *args, **kwargs):
            if self == f:
                raise OSError("Permission denied")
            return original_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", patched_read_text)

        analyzer = StaticAnalyzer(rules=[])
        findings = analyzer.analyze_file(f)

        assert len(findings) == 1
        assert findings[0].rule_id == "PARSE_ERROR"
        assert findings[0].severity == Severity.INFO
        assert "Permission denied" in findings[0].message

    def test_unreadable_file_does_not_stop_other_files(self, tmp_path, monkeypatch):
        """An OSError on one file does not prevent other files from being analyzed."""
        rule, calls = _make_recording_rule("MCP_REC")
        locked = _write_py(tmp_path, "a_locked.py", "x = 1\n")
        _write_py(tmp_path, "b_valid.py", "y = 2\n")

        original_read_text = Path.read_text

        def patched_read_text(self, *args, **kwargs):
            if self == locked:
                raise OSError("Permission denied")
            return original_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", patched_read_text)

        analyzer = StaticAnalyzer(rules=[rule])
        result = analyzer.analyze_path(tmp_path)

        analyzed_paths = {path for path, _ in calls}
        assert any("b_valid.py" in p for p in analyzed_paths)

        parse_errors = [f for f in result.findings if f.rule_id == "PARSE_ERROR"]
        assert len(parse_errors) == 1


# ---------------------------------------------------------------------------
# _is_excluded ValueError fallback (lines 239–240)
# ---------------------------------------------------------------------------


class TestIsExcludedValueErrorFallback:
    """Lines 239–240: when file_path.relative_to(root) raises ValueError
    (file is outside the root), _is_excluded falls back to the absolute path string.
    """

    def test_file_outside_root_uses_absolute_path_for_matching(self, tmp_path):
        """A file outside the scan root still matches exclusion patterns via
        its absolute path string.
        """
        # Create two separate directories so the file is outside the root
        root_dir = tmp_path / "root"
        root_dir.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()

        outside_file = outside_dir / "excluded.py"
        outside_file.write_text("x = 1\n", encoding="utf-8")

        # Pattern matches the filename
        result = StaticAnalyzer._is_excluded(
            outside_file,
            root_dir,  # outside_file is NOT relative to root_dir → ValueError
            ["excluded.py"],
        )
        assert result is True

    def test_file_outside_root_no_pattern_match_not_excluded(self, tmp_path):
        """A file outside the root that doesn't match any pattern is not excluded."""
        root_dir = tmp_path / "root"
        root_dir.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()

        outside_file = outside_dir / "server.py"
        outside_file.write_text("x = 1\n", encoding="utf-8")

        result = StaticAnalyzer._is_excluded(
            outside_file,
            root_dir,
            ["excluded.py"],
        )
        assert result is False
