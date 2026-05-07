"""Property-based tests for SSRF rules — no false positives on clean files.

# Feature: mcp-scan, Property 3: SSRF rules produce no false positives on clean files

**Validates: Requirements 4.6**

Property 3: For any Python source file in which no MCP tool handler function
passes a tainted parameter value to an HTTP client call (httpx, requests,
urllib), subprocess call with shell=True, or open() call, the StaticAnalyzer
SHALL emit zero findings for rules MCP001–005.
"""

from __future__ import annotations

import ast
import textwrap

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from mcp_scan.rules.ssrf import (
    Mcp001TaintedUrlRule,
    Mcp002MissingTimeoutRule,
    Mcp003UrllibUrlOpenRule,
    Mcp004SubprocessShellRule,
    Mcp005TaintedOpenRule,
)
from mcp_scan.static.analyzer import _build_alias_map

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ALL_RULES = [
    Mcp001TaintedUrlRule(),
    Mcp002MissingTimeoutRule(),
    Mcp003UrllibUrlOpenRule(),
    Mcp004SubprocessShellRule(),
    Mcp005TaintedOpenRule(),
]

_SSRF_RULE_IDS = {"MCP001", "MCP002", "MCP003", "MCP004", "MCP005"}


def _check_all_ssrf_rules(source: str) -> list:
    """Run all five SSRF rules against *source* and return combined findings."""
    src = textwrap.dedent(source)
    tree = ast.parse(src, filename="<test>")
    alias_map = _build_alias_map(tree)
    findings = []
    for rule in _ALL_RULES:
        findings.extend(rule.check(tree, "<test>", alias_map))
    return [f for f in findings if f.rule_id in _SSRF_RULE_IDS]


# ---------------------------------------------------------------------------
# Clean source templates
#
# Each template is a complete, valid Python snippet representing an MCP tool
# handler that is "clean" with respect to all five SSRF rules:
#
#   MCP001 — no tainted URL to httpx/requests (literal URLs only)
#   MCP002 — all HTTP calls include timeout=
#   MCP003 — no tainted URL to urllib.request.urlopen (literal URLs only)
#   MCP004 — no subprocess with shell=True and tainted arg
#   MCP005 — no tainted path to open() (literal paths only)
# ---------------------------------------------------------------------------

# Literal URL values used in templates (all are string constants, never params)
_LITERAL_URLS = [
    '"https://api.example.com/data"',
    '"https://httpbin.org/get"',
    '"http://localhost:8080/health"',
    '"https://example.com/api/v1/resource"',
]

# Literal file paths used in templates
_LITERAL_PATHS = [
    '"/tmp/output.txt"',
    '"/var/log/app.log"',
    '"/data/report.csv"',
]

# Literal shell commands (not tainted)
_LITERAL_CMDS = [
    '"ls -la"',
    '"echo hello"',
    '"date"',
]

# Timeout values
_TIMEOUT_VALUES = ["5", "10", "30", "60"]

# Clean template strings — each is a valid Python snippet with no taint issues
_CLEAN_TEMPLATES = [
    # --- httpx with literal URL and timeout ---
    """\
import httpx

@mcp.tool()
def fetch_data(query: str) -> str:
    result = httpx.get("https://api.example.com/data", timeout=30)
    return result.text
""",
    """\
import httpx

@mcp.tool()
def post_data(payload: str) -> str:
    result = httpx.post("https://api.example.com/submit", timeout=10)
    return result.text
""",
    """\
import httpx

@mcp.tool()
def put_resource(body: str) -> str:
    result = httpx.put("https://api.example.com/resource", timeout=5)
    return result.text
""",
    """\
import httpx

@mcp.tool()
def delete_resource(resource_id: str) -> str:
    result = httpx.delete("https://api.example.com/resource", timeout=10)
    return result.text
""",
    # --- requests with literal URL and timeout ---
    """\
import requests

@mcp.tool()
def search(query: str) -> str:
    result = requests.get("https://api.example.com/search", timeout=10)
    return result.text
""",
    """\
import requests

@mcp.tool()
def submit(data: str) -> str:
    result = requests.post("https://api.example.com/submit", timeout=5)
    return result.text
""",
    # --- urllib.request.urlopen with literal URL ---
    """\
import urllib.request

@mcp.tool()
def open_url(query: str) -> str:
    response = urllib.request.urlopen("https://api.example.com/data")
    return response.read().decode()
""",
    # --- subprocess without shell=True (safe) ---
    """\
import subprocess

@mcp.tool()
def run_cmd(name: str) -> str:
    result = subprocess.run(["ls", "-la"], capture_output=True)
    return result.stdout.decode()
""",
    # --- subprocess with shell=True but literal (non-tainted) command ---
    """\
import subprocess

@mcp.tool()
def list_files(directory: str) -> str:
    result = subprocess.run("ls -la", shell=True, capture_output=True)
    return result.stdout.decode()
""",
    # --- open() with literal path ---
    """\
@mcp.tool()
def read_config(section: str) -> str:
    with open("/etc/app/config.txt") as f:
        return f.read()
""",
    """\
@mcp.tool()
def read_report(name: str) -> str:
    with open("/data/report.csv") as f:
        return f.read()
""",
    # --- MCP tool with no HTTP/subprocess/file calls at all ---
    """\
@mcp.tool()
def greet(name: str) -> str:
    return f"Hello, {name}!"
""",
    """\
@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b
""",
    """\
@mcp.tool()
def echo(message: str) -> str:
    return message
""",
    # --- File with no MCP tool handlers at all ---
    """\
import httpx
import subprocess

def helper(url):
    return httpx.get(url)

def run(cmd):
    subprocess.run(cmd, shell=True)
""",
    """\
x = 1
y = 2
z = x + y
""",
    """\
def plain_function(url):
    import requests
    return requests.get(url)
""",
    # --- Multiple clean MCP tools in one file ---
    """\
import httpx
import subprocess

@mcp.tool()
def fetch(query: str) -> str:
    return httpx.get("https://api.example.com/search", timeout=10).text

@mcp.tool()
def run_safe(name: str) -> str:
    result = subprocess.run(["echo", name], capture_output=True)
    return result.stdout.decode()

@mcp.tool()
def read_fixed(section: str) -> str:
    with open("/etc/config.txt") as f:
        return f.read()
""",
    # --- httpx.request with literal URL and timeout ---
    """\
import httpx

@mcp.tool()
def make_request(method: str) -> str:
    result = httpx.request("GET", "https://api.example.com/data", timeout=30)
    return result.text
""",
    # --- Validated inputs (sanitized via allowlist) ---
    """\
import httpx
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.example.com", "httpbin.org"}

@mcp.tool()
def safe_fetch(url: str) -> str:
    if urlparse(url).hostname in ALLOWED_HOSTS:
        return httpx.get(url, timeout=10).text
    return ""
""",
    """\
ALLOWED_FILES = {"/data/report.txt", "/data/summary.csv"}

@mcp.tool()
def safe_read(filename: str) -> str:
    if filename in ALLOWED_FILES:
        with open(filename) as f:
            return f.read()
    return ""
""",
]


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Strategy: sample from the pre-written clean templates
clean_template_strategy = st.sampled_from(_CLEAN_TEMPLATES)

# Strategy: build a clean httpx snippet with a generated literal URL and timeout
# The URL is always a string constant (never a variable reference)
_url_path_strategy = st.text(
    alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd"),
        whitelist_characters="-_/.",
    ),
    min_size=1,
    max_size=30,
).map(lambda s: s.strip("/") or "data")

_timeout_strategy = st.integers(min_value=1, max_value=300)

_http_method_strategy = st.sampled_from(["get", "post", "put", "delete", "patch"])

_http_client_strategy = st.sampled_from(["httpx", "requests"])


@st.composite
def clean_httpx_snippet(draw) -> str:
    """Generate a clean MCP tool handler using httpx/requests with a literal URL."""
    client = draw(_http_client_strategy)
    method = draw(_http_method_strategy)
    path = draw(_url_path_strategy)
    timeout = draw(_timeout_strategy)
    url = f"https://api.example.com/{path}"
    return (
        f"import {client}\n\n"
        f"@mcp.tool()\n"
        f"def handler(param: str) -> str:\n"
        f'    result = {client}.{method}("{url}", timeout={timeout})\n'
        f"    return result.text\n"
    )


@st.composite
def clean_subprocess_snippet(draw) -> str:
    """Generate a clean MCP tool handler using subprocess safely."""
    # Either no shell=True, or shell=True with a literal command
    use_shell = draw(st.booleans())
    if use_shell:
        cmd = draw(st.sampled_from(['"ls -la"', '"echo hello"', '"date"', '"pwd"']))
        return (
            "import subprocess\n\n"
            "@mcp.tool()\n"
            "def handler(param: str) -> str:\n"
            f"    result = subprocess.run({cmd}, shell=True, capture_output=True)\n"
            "    return result.stdout.decode()\n"
        )
    else:
        return (
            "import subprocess\n\n"
            "@mcp.tool()\n"
            "def handler(param: str) -> str:\n"
            '    result = subprocess.run(["ls", "-la"], capture_output=True)\n'
            "    return result.stdout.decode()\n"
        )


@st.composite
def clean_open_snippet(draw) -> str:
    """Generate a clean MCP tool handler using open() with a literal path."""
    path = draw(st.sampled_from([
        '"/tmp/output.txt"',
        '"/var/log/app.log"',
        '"/data/report.csv"',
        '"/etc/config.txt"',
    ]))
    return (
        "@mcp.tool()\n"
        "def handler(param: str) -> str:\n"
        f"    with open({path}) as f:\n"
        "        return f.read()\n"
    )


@st.composite
def clean_no_http_snippet(draw) -> str:
    """Generate a clean MCP tool handler with no HTTP/subprocess/file calls."""
    body = draw(st.sampled_from([
        '    return f"Hello, {param}!"',
        "    return param.upper()",
        "    return len(param)",
        "    return param[::-1]",
        '    return "ok"',
    ]))
    return (
        "@mcp.tool()\n"
        "def handler(param: str) -> str:\n"
        f"{body}\n"
    )


# Combined strategy: pick from any clean source type
clean_source_strategy = st.one_of(
    clean_template_strategy,
    clean_httpx_snippet(),
    clean_subprocess_snippet(),
    clean_open_snippet(),
    clean_no_http_snippet(),
)


# ---------------------------------------------------------------------------
# Property 3: SSRF rules produce no false positives on clean files
# ---------------------------------------------------------------------------


@settings(
    max_examples=25,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
@given(source=clean_source_strategy)
def test_ssrf_rules_no_false_positives_on_clean_files(source: str) -> None:
    """Property 3: SSRF rules produce no false positives on clean files.

    For any Python source file in which no MCP tool handler function passes a
    tainted parameter value to an HTTP client call (httpx, requests, urllib),
    subprocess call with shell=True, or open() call, the StaticAnalyzer SHALL
    emit zero findings for rules MCP001–005.

    # Feature: mcp-scan, Property 3: SSRF rules produce no false positives on clean files
    **Validates: Requirements 4.6**
    """
    # Ensure the generated source is valid Python (parseable)
    try:
        ast.parse(textwrap.dedent(source))
    except SyntaxError as exc:
        # If the generated source has a syntax error, skip this example
        # (the strategy should not produce invalid Python, but be defensive)
        pytest.skip(f"Generated source has syntax error: {exc}")

    findings = _check_all_ssrf_rules(source)

    assert findings == [], (
        f"Expected zero findings for clean source, but got {len(findings)} finding(s):\n"
        + "\n".join(
            f"  [{f.rule_id}] {f.message} at {f.location}"
            for f in findings
        )
        + f"\n\nSource:\n{textwrap.dedent(source)}"
    )
