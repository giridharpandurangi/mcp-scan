"""Property-based tests for StaticAnalyzer determinism and rule coverage.

# Feature: mcp-scan, Property 2: Static analysis determinism
# Feature: mcp-scan, Property 8: All rules are applied to every analyzed file

**Validates: Requirements 2.8, 2.5**
"""

from __future__ import annotations

import ast
import os
import tempfile
from unittest.mock import MagicMock, patch

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from mcp_scan.models import Finding, Severity
from mcp_scan.rules import Rule, discover_rules
from mcp_scan.static.analyzer import StaticAnalyzer

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Valid Python source templates — simple constructs that are syntactically valid
_SIMPLE_PYTHON_SOURCES = [
    "x = 1\n",
    "def foo():\n    pass\n",
    "class Foo:\n    pass\n",
    "import os\nx = os.getcwd()\n",
    "x = 1\ny = 2\nz = x + y\n",
    "for i in range(10):\n    print(i)\n",
    "if True:\n    x = 1\nelse:\n    x = 2\n",
    "try:\n    x = 1\nexcept Exception:\n    pass\n",
    "a = [1, 2, 3]\nb = {k: v for k, v in enumerate(a)}\n",
    "from pathlib import Path\np = Path('.')\n",
]

# Python sources with syntax errors — still deterministic (PARSE_ERROR finding)
_SYNTAX_ERROR_SOURCES = [
    "def foo(\n",  # unclosed paren
    "class Foo\n    pass\n",  # missing colon
    "x = (\n",  # unclosed expression
    "import\n",  # incomplete import
]

# Python sources with MCP tool patterns that trigger rules
_MCP_TOOL_SOURCES = [
    # SSRF pattern: tainted URL to httpx.get
    "import httpx\n\n@mcp.tool()\ndef fetch_data(url):\n    return httpx.get(url)\n",
    # SSRF pattern: tainted URL to requests.get
    "import requests\n\n@mcp.tool()\ndef fetch(url):\n    return requests.get(url)\n",
    # Subprocess with shell=True
    "import subprocess\n\n@mcp.tool()\ndef run_cmd(cmd):\n    return subprocess.run(cmd, shell=True)\n",
    # Open with tainted path
    "@mcp.tool()\ndef read_file(path):\n    return open(path).read()\n",
    # Hardcoded secret
    "api_key = 'sk-1234567890abcdef'\n",
    # Multiple imports and tool
    (
        "import httpx\nfrom urllib.parse import urlparse\n\n"
        "@mcp.tool()\ndef handler(url):\n    parsed = urlparse(url)\n    return httpx.get(url)\n"
    ),
]

# Combined strategy: pick from any of the three categories
python_source_strategy = st.one_of(
    st.sampled_from(_SIMPLE_PYTHON_SOURCES),
    st.sampled_from(_SYNTAX_ERROR_SOURCES),
    st.sampled_from(_MCP_TOOL_SOURCES),
)


# ---------------------------------------------------------------------------
# Property 2: Static analysis determinism
# ---------------------------------------------------------------------------


@settings(max_examples=25, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(source=python_source_strategy)
def test_static_analysis_is_deterministic(source: str) -> None:
    """Property 2: Static analysis determinism.

    For any Python source string (valid, invalid, or containing MCP tool
    patterns), running StaticAnalyzer twice on the same file SHALL produce
    identical Finding lists.

    # Feature: mcp-scan, Property 2: Static analysis determinism
    **Validates: Requirements 2.8**
    """
    # Write source to a temp file with .py suffix
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            f.write(source)

        # Use auto-discovered rules for a realistic determinism check
        analyzer = StaticAnalyzer()

        findings_1 = analyzer.analyze_file(tmp_path)
        findings_2 = analyzer.analyze_file(tmp_path)

        assert findings_1 == findings_2, (
            f"analyze_file() produced different results on two runs — not deterministic.\n"
            f"Run 1: {findings_1}\n"
            f"Run 2: {findings_2}\n"
            f"Source:\n{source}"
        )
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Property 8: All rules are applied to every analyzed file
# ---------------------------------------------------------------------------


@settings(max_examples=25, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(source=python_source_strategy)
def test_all_rules_applied_to_every_file(source: str) -> None:
    """Property 8: All rules are applied to every analyzed file.

    For N registered rules and any source file, assert ``check()`` is called
    exactly once per rule per file analyzed.

    # Feature: mcp-scan, Property 8: All rules are applied to every analyzed file
    **Validates: Requirements 2.5**
    """
    # Discover the real rules so N is the actual registered count
    real_rules = discover_rules()
    n_rules = len(real_rules)

    # Build spy wrappers: replace each rule's check() with a MagicMock that
    # delegates to the original implementation so findings are still produced.
    # Keep a reference to the original bound method for restoration.
    original_checks: list = []
    mocks: list[MagicMock] = []

    for rule in real_rules:
        original_check = rule.check
        original_checks.append(original_check)
        mock = MagicMock(side_effect=original_check)
        rule.check = mock  # type: ignore[method-assign]
        mocks.append(mock)

    # Write source to a temp file with .py suffix
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            f.write(source)

        # Construct analyzer with the spy rules (bypasses auto-discovery)
        analyzer = StaticAnalyzer(rules=real_rules)
        analyzer.analyze_file(tmp_path)

        # For syntax-error sources, analyze_file returns early with a PARSE_ERROR
        # finding and never dispatches rules — that is correct behaviour per the
        # spec (rules operate on a parsed AST; if parsing fails there is no AST).
        # We detect this case by attempting to parse the source ourselves.
        try:
            ast.parse(source)
            parse_ok = True
        except SyntaxError:
            parse_ok = False

        if parse_ok:
            # Every rule must have been called exactly once
            for rule, mock in zip(real_rules, mocks):
                assert mock.call_count == 1, (
                    f"Rule {rule.rule_id} check() was called "
                    f"{mock.call_count} time(s) instead of exactly 1.\n"
                    f"Source:\n{source}"
                )
        else:
            # Syntax error: rules must NOT have been called (no AST to dispatch on)
            for rule, mock in zip(real_rules, mocks):
                assert mock.call_count == 0, (
                    f"Rule {rule.rule_id} check() was called "
                    f"{mock.call_count} time(s) on a file that failed to parse.\n"
                    f"Source:\n{source}"
                )

    finally:
        os.unlink(tmp_path)
        # Restore original check methods to avoid cross-test contamination
        for rule, original_check in zip(real_rules, original_checks):
            rule.check = original_check  # type: ignore[method-assign]
