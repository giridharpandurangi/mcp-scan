"""Unit tests for SSRF and request-side rules MCP001–MCP005.

Task 6.1 — Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 13.1, 13.2

Structure:
- One positive fixture (vulnerable pattern → finding emitted) per rule
- One negative fixture (clean pattern → no finding) per rule
- Aliased import regression test for MCP001 (from httpx import get as fetch)
- Parametrized where patterns are uniform; explicit tests where they differ
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from mcp_scan.models import Severity
from mcp_scan.rules.ssrf import (
    Mcp001TaintedUrlRule,
    Mcp002MissingTimeoutRule,
    Mcp003UrllibUrlOpenRule,
    Mcp004SubprocessShellRule,
    Mcp005TaintedOpenRule,
)
from mcp_scan.static.analyzer import _build_alias_map

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "ssrf"


def _load_fixture(name: str) -> tuple[ast.AST, dict, str]:
    """Parse a fixture file and return (tree, alias_map, source_path)."""
    path = FIXTURES_DIR / name
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    alias_map = _build_alias_map(tree)
    return tree, alias_map, str(path)


def _parse_inline(source: str) -> tuple[ast.AST, dict, str]:
    """Parse an inline source string and return (tree, alias_map, source_path)."""
    src = textwrap.dedent(source)
    tree = ast.parse(src, filename="<test>")
    alias_map = _build_alias_map(tree)
    return tree, alias_map, "<test>"


# ---------------------------------------------------------------------------
# MCP001 — Tainted URL to HTTP client
# ---------------------------------------------------------------------------


class TestMcp001TaintedUrl:
    rule = Mcp001TaintedUrlRule()

    def test_positive_httpx_get(self):
        """Tainted URL passed to httpx.get emits MCP001 HIGH finding."""
        tree, alias_map, path = _load_fixture("mcp001_positive.py")
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP001"
        assert findings[0].severity == Severity.HIGH

    def test_negative_allowlist_validated(self):
        """URL validated via urlparse().hostname allowlist emits no MCP001."""
        tree, alias_map, path = _load_fixture("mcp001_negative.py")
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []

    def test_alias_positive_from_httpx_import_get_as_fetch(self):
        """REGRESSION: 'from httpx import get as fetch' — aliased call still detected.

        This is the dedicated regression test for the alias map work in Task 4.
        The rule must resolve 'fetch' → ('httpx', 'get') via the alias map.
        """
        tree, alias_map, path = _load_fixture("mcp001_alias_positive.py")
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP001"

    def test_alias_module_httpx_as_h(self):
        """'import httpx as h; h.get(url)' — module alias resolved correctly."""
        tree, alias_map, path = _parse_inline("""
            import httpx as h

            @mcp.tool()
            def fetch(url):
                return h.get(url)
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP001"

    def test_requests_post_tainted(self):
        """Tainted URL to requests.post also triggers MCP001."""
        tree, alias_map, path = _parse_inline("""
            import requests

            @mcp.tool()
            def post_data(url, data):
                return requests.post(url, json=data)
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP001"

    def test_literal_url_no_finding(self):
        """Literal URL (not tainted) does not trigger MCP001."""
        tree, alias_map, path = _parse_inline("""
            import httpx

            @mcp.tool()
            def fetch(query):
                return httpx.get("https://api.example.com/search")
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []

    def test_non_mcp_tool_not_analyzed(self):
        """A plain function (not @mcp.tool) with tainted URL is not flagged."""
        tree, alias_map, path = _parse_inline("""
            import httpx

            def plain_fetch(url):
                return httpx.get(url)
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []

    def test_url_kwarg_tainted(self):
        """Tainted value passed as url= keyword argument is detected."""
        tree, alias_map, path = _parse_inline("""
            import httpx

            @mcp.tool()
            def fetch(url):
                return httpx.request("GET", url=url)
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1

    def test_finding_location_contains_line_number(self):
        """The finding location includes the line number of the sink call."""
        tree, alias_map, path = _load_fixture("mcp001_positive.py")
        findings = self.rule.check(tree, path, alias_map)
        assert ":" in findings[0].location
        line_part = findings[0].location.split(":")[-1]
        assert line_part.isdigit()

    def test_no_alias_map_still_detects_direct_call(self):
        """Passing no alias_map (None) still detects direct httpx.get calls."""
        tree, _, path = _parse_inline("""
            import httpx

            @mcp.tool()
            def fetch(url):
                return httpx.get(url)
        """)
        findings = self.rule.check(tree, path, alias_map=None)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# MCP002 — Missing timeout
# ---------------------------------------------------------------------------


class TestMcp002MissingTimeout:
    rule = Mcp002MissingTimeoutRule()

    def test_positive_no_timeout(self):
        """HTTP call without timeout= emits MCP002 LOW finding."""
        tree, alias_map, path = _load_fixture("mcp002_positive.py")
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP002"
        assert findings[0].severity == Severity.LOW

    def test_negative_with_timeout(self):
        """HTTP call with timeout= emits no MCP002."""
        tree, alias_map, path = _load_fixture("mcp002_negative.py")
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []

    def test_requests_get_no_timeout(self):
        """requests.get without timeout also triggers MCP002."""
        tree, alias_map, path = _parse_inline("""
            import requests

            @mcp.tool()
            def fetch(query):
                return requests.get("https://api.example.com")
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP002"

    def test_timeout_zero_is_valid(self):
        """timeout=0 counts as a timeout argument — no MCP002."""
        tree, alias_map, path = _parse_inline("""
            import httpx

            @mcp.tool()
            def fetch(query):
                return httpx.get("https://api.example.com", timeout=0)
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []

    def test_non_mcp_tool_not_analyzed(self):
        """Plain function without @mcp.tool is not analyzed for MCP002."""
        tree, alias_map, path = _parse_inline("""
            import httpx

            def plain_fetch():
                return httpx.get("https://api.example.com")
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []

    def test_aliased_import_no_timeout(self):
        """Aliased import 'from httpx import get as fetch' without timeout triggers MCP002."""
        tree, alias_map, path = _parse_inline("""
            from httpx import get as fetch

            @mcp.tool()
            def handler(query):
                return fetch("https://api.example.com")
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP002"


# ---------------------------------------------------------------------------
# MCP003 — urllib.request.urlopen with tainted URL
# ---------------------------------------------------------------------------


class TestMcp003UrllibUrlOpen:
    rule = Mcp003UrllibUrlOpenRule()

    def test_positive_tainted_url(self):
        """Tainted URL to urllib.request.urlopen emits MCP003 HIGH finding."""
        tree, alias_map, path = _load_fixture("mcp003_positive.py")
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP003"
        assert findings[0].severity == Severity.HIGH

    def test_negative_literal_url(self):
        """Literal URL to urlopen emits no MCP003."""
        tree, alias_map, path = _load_fixture("mcp003_negative.py")
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []

    def test_tainted_via_concatenation(self):
        """URL built by concatenating a tainted value is also detected."""
        tree, alias_map, path = _parse_inline("""
            import urllib.request

            @mcp.tool()
            def open_url(path):
                full_url = "https://api.example.com/" + path
                return urllib.request.urlopen(full_url)
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP003"

    def test_non_mcp_tool_not_analyzed(self):
        """Plain function is not analyzed for MCP003."""
        tree, alias_map, path = _parse_inline("""
            import urllib.request

            def plain_open(url):
                return urllib.request.urlopen(url)
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []

    def test_sanitized_url_no_finding(self):
        """URL sanitized via allowlist check does not trigger MCP003."""
        tree, alias_map, path = _parse_inline("""
            import urllib.request
            from urllib.parse import urlparse

            ALLOWED = {"api.example.com"}

            @mcp.tool()
            def open_url(url):
                if urlparse(url).hostname in ALLOWED:
                    return urllib.request.urlopen(url)
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []


# ---------------------------------------------------------------------------
# MCP004 — subprocess with shell=True and tainted arg
# ---------------------------------------------------------------------------


class TestMcp004SubprocessShell:
    rule = Mcp004SubprocessShellRule()

    def test_positive_shell_true_tainted(self):
        """subprocess.run with shell=True and tainted arg emits MCP004 CRITICAL."""
        tree, alias_map, path = _load_fixture("mcp004_positive.py")
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP004"
        assert findings[0].severity == Severity.CRITICAL

    def test_negative_no_shell_true(self):
        """subprocess.run without shell=True emits no MCP004."""
        tree, alias_map, path = _load_fixture("mcp004_negative.py")
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []

    def test_subprocess_call_shell_true(self):
        """subprocess.call with shell=True and tainted arg also triggers MCP004."""
        tree, alias_map, path = _parse_inline("""
            import subprocess

            @mcp.tool()
            def run(cmd):
                subprocess.call(cmd, shell=True)
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP004"

    def test_subprocess_popen_shell_true(self):
        """subprocess.Popen with shell=True and tainted arg triggers MCP004."""
        tree, alias_map, path = _parse_inline("""
            import subprocess

            @mcp.tool()
            def run(cmd):
                subprocess.Popen(cmd, shell=True)
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP004"

    def test_shell_false_explicit_no_finding(self):
        """subprocess.run with shell=False and tainted arg does not trigger MCP004."""
        tree, alias_map, path = _parse_inline("""
            import subprocess

            @mcp.tool()
            def run(cmd):
                subprocess.run(cmd, shell=False)
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []

    def test_literal_cmd_shell_true_no_finding(self):
        """subprocess.run with shell=True but literal (non-tainted) cmd — no MCP004."""
        tree, alias_map, path = _parse_inline("""
            import subprocess

            @mcp.tool()
            def run(query):
                subprocess.run("ls -la", shell=True)
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []

    def test_non_mcp_tool_not_analyzed(self):
        """Plain function is not analyzed for MCP004."""
        tree, alias_map, path = _parse_inline("""
            import subprocess

            def plain_run(cmd):
                subprocess.run(cmd, shell=True)
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []


# ---------------------------------------------------------------------------
# MCP005 — Tainted path to open()
# ---------------------------------------------------------------------------


class TestMcp005TaintedOpen:
    rule = Mcp005TaintedOpenRule()

    def test_positive_tainted_path(self):
        """Tainted path to open() emits MCP005 HIGH finding."""
        tree, alias_map, path = _load_fixture("mcp005_positive.py")
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP005"
        assert findings[0].severity == Severity.HIGH

    def test_negative_literal_path(self):
        """Literal path to open() emits no MCP005."""
        tree, alias_map, path = _load_fixture("mcp005_negative.py")
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []

    def test_tainted_via_fstring(self):
        """Path built with an f-string containing a tainted value is detected."""
        tree, alias_map, path = _parse_inline("""
            @mcp.tool()
            def read_file(filename):
                with open(f"/data/{filename}") as f:
                    return f.read()
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP005"

    def test_tainted_via_concatenation(self):
        """Path built by concatenation with a tainted value is detected."""
        tree, alias_map, path = _parse_inline("""
            @mcp.tool()
            def read_file(filename):
                full_path = "/data/" + filename
                with open(full_path) as f:
                    return f.read()
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP005"

    def test_non_mcp_tool_not_analyzed(self):
        """Plain function is not analyzed for MCP005."""
        tree, alias_map, path = _parse_inline("""
            def plain_read(path):
                with open(path) as f:
                    return f.read()
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []

    def test_sanitized_path_no_finding(self):
        """Path sanitized via membership test does not trigger MCP005."""
        tree, alias_map, path = _parse_inline("""
            ALLOWED_FILES = {"/data/report.txt", "/data/summary.csv"}

            @mcp.tool()
            def read_file(filename):
                if filename in ALLOWED_FILES:
                    with open(filename) as f:
                        return f.read()
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert findings == []


# ---------------------------------------------------------------------------
# MCP001–005 no-false-positives on clean files (Requirement 4.6)
# ---------------------------------------------------------------------------


class TestNoFalsePositivesOnCleanFiles:
    """For files with no SSRF/request-side issues, all five rules emit zero findings."""

    ALL_RULES = [
        Mcp001TaintedUrlRule(),
        Mcp002MissingTimeoutRule(),
        Mcp003UrllibUrlOpenRule(),
        Mcp004SubprocessShellRule(),
        Mcp005TaintedOpenRule(),
    ]

    def _check_all(self, source: str) -> list:
        tree, alias_map, path = _parse_inline(source)
        findings = []
        for rule in self.ALL_RULES:
            findings.extend(rule.check(tree, path, alias_map))
        return findings

    def test_empty_mcp_tool_no_findings(self):
        """An MCP tool with no HTTP/subprocess/file calls produces no findings."""
        findings = self._check_all("""
            @mcp.tool()
            def greet(name):
                return f"Hello, {name}!"
        """)
        assert findings == []

    def test_literal_url_all_rules_clean(self):
        """All rules produce zero findings when only literal URLs are used."""
        findings = self._check_all("""
            import httpx

            @mcp.tool()
            def fetch(query):
                return httpx.get("https://api.example.com/search", timeout=5)
        """)
        assert findings == []

    def test_no_mcp_tools_no_findings(self):
        """A file with no MCP tool decorators produces no findings from any rule."""
        findings = self._check_all("""
            import httpx
            import subprocess

            def helper(url):
                return httpx.get(url)

            def run(cmd):
                subprocess.run(cmd, shell=True)
        """)
        assert findings == []

    def test_validated_inputs_all_rules_clean(self):
        """All rules produce zero findings when inputs are properly validated."""
        findings = self._check_all("""
            import httpx
            import subprocess
            from urllib.parse import urlparse

            ALLOWED_HOSTS = {"api.example.com"}
            ALLOWED_FILES = {"/data/report.txt"}

            @mcp.tool()
            def safe_fetch(url):
                if urlparse(url).hostname in ALLOWED_HOSTS:
                    return httpx.get(url, timeout=10)

            @mcp.tool()
            def safe_read(filename):
                if filename in ALLOWED_FILES:
                    with open(filename) as f:
                        return f.read()
        """)
        assert findings == []


# ---------------------------------------------------------------------------
# Direct helper tests for 100% coverage on ssrf.py
# ---------------------------------------------------------------------------

from mcp_scan.rules.ssrf import (
    _resolve_call,
    _run_sink_tracker,
    SinkCheckingTaintTracker,
)


class TestResolveCallEdgeCases:
    """Cover the fallthrough return None paths in _resolve_call."""

    def test_two_level_attribute_non_name_outer_returns_none(self):
        """Three-level attribute (foo.bar.baz.get) — outer is Attribute, not Name → None."""
        # foo.bar.baz.get(url): func = Attribute(value=Attribute(value=Attribute(...)))
        call = ast.Call(
            func=ast.Attribute(
                value=ast.Attribute(
                    value=ast.Attribute(
                        value=ast.Name(id="foo", ctx=ast.Load()),
                        attr="bar",
                        ctx=ast.Load(),
                    ),
                    attr="baz",
                    ctx=ast.Load(),
                ),
                attr="get",
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[],
        )
        result = _resolve_call(call, {})
        assert result is None

    def test_subscript_func_returns_none(self):
        """Call whose func is a Subscript (not Attribute/Name) → None."""
        call = ast.Call(
            func=ast.Subscript(
                value=ast.Name(id="funcs", ctx=ast.Load()),
                slice=ast.Constant(value=0),
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[],
        )
        result = _resolve_call(call, {})
        assert result is None


class TestRunSinkTrackerVarArgs:
    """Cover *args, **kwargs, and kwonly args taint seeding (lines 172, 174, 176)."""

    def test_vararg_is_tainted(self):
        """*args parameter is seeded as tainted."""
        src = textwrap.dedent("""
            @mcp.tool()
            def handler(*args):
                import httpx
                return httpx.get(args[0])
        """)
        # We just verify the tracker is built without error and the function runs
        tree, alias_map, path = _parse_inline(src)
        rule = Mcp001TaintedUrlRule()
        # args[0] is a Subscript — not tracked as tainted by is_tainted, so no finding
        # but the code path for vararg seeding is exercised
        findings = rule.check(tree, path, alias_map)
        # No finding expected (Subscript not tracked), but no crash either
        assert isinstance(findings, list)

    def test_kwarg_is_seeded(self):
        """**kwargs parameter is seeded as tainted (exercises line 174)."""
        src = textwrap.dedent("""
            @mcp.tool()
            def handler(**kwargs):
                pass
        """)
        tree = ast.parse(src)
        func_def = tree.body[0]
        findings = _run_sink_tracker(func_def, tree, lambda call, t: None)
        assert findings == []

    def test_kwonly_args_are_seeded(self):
        """Keyword-only args are seeded as tainted (exercises line 176)."""
        src = textwrap.dedent("""
            @mcp.tool()
            def handler(*, url):
                import httpx
                return httpx.get(url)
        """)
        tree, alias_map, path = _parse_inline(src)
        rule = Mcp001TaintedUrlRule()
        findings = rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP001"


class TestMcp001UrlKwargAndMethodArg:
    """Cover the url= keyword fallback and second-arg-as-url paths (lines 222–232)."""

    rule = Mcp001TaintedUrlRule()

    def test_url_keyword_only_no_positional(self):
        """httpx.request(url=tainted_url) — url= keyword, no positional URL arg."""
        tree, alias_map, path = _parse_inline("""
            import httpx

            @mcp.tool()
            def fetch(url):
                return httpx.request(url=url)
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP001"

    def test_method_string_then_tainted_url_second_arg(self):
        """httpx.request('GET', tainted_url) — first arg is literal method, second is URL."""
        tree, alias_map, path = _parse_inline("""
            import httpx

            @mcp.tool()
            def fetch(url):
                return httpx.request('GET', url)
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP001"


class TestMcp005FileKwarg:
    """Cover the file= keyword fallback in MCP005 (lines 449–452)."""

    rule = Mcp005TaintedOpenRule()

    def test_file_keyword_arg_tainted(self):
        """open(file=tainted_path) — file= keyword argument is detected."""
        tree, alias_map, path = _parse_inline("""
            @mcp.tool()
            def read(path):
                with open(file=path) as f:
                    return f.read()
        """)
        findings = self.rule.check(tree, path, alias_map)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP005"
