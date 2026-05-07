"""Property-based tests for secrets rules — no false positives on clean files.

# Feature: mcp-scan, Property 4: Secrets rules produce no false positives on clean files

**Validates: Requirements 5.6**

Property 4: For any Python source file that contains no string literals assigned
to credential-named variables (api_key, token, password, etc.) and no http:// URLs
in auth contexts, the StaticAnalyzer SHALL emit zero findings for rules MCP010–014.
"""

from __future__ import annotations

import ast
import textwrap

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from mcp_scan.rules.secrets import (
    Mcp010HardcodedApiKeyRule,
    Mcp011HardcodedPasswordRule,
    Mcp012InsecureHttpRule,
    Mcp013MissingPkceRule,
    Mcp014CredentialLoggingRule,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ALL_RULES = [
    Mcp010HardcodedApiKeyRule(),
    Mcp011HardcodedPasswordRule(),
    Mcp012InsecureHttpRule(),
    Mcp013MissingPkceRule(),
    Mcp014CredentialLoggingRule(),
]

_SECRETS_RULE_IDS = {"MCP010", "MCP011", "MCP012", "MCP013", "MCP014"}


def _check_all_secrets_rules(source: str) -> list:
    """Run all five secrets rules against *source* and return combined findings."""
    src = textwrap.dedent(source)
    tree = ast.parse(src, filename="<test>")
    findings = []
    for rule in _ALL_RULES:
        findings.extend(rule.check(tree, "<test>"))
    return [f for f in findings if f.rule_id in _SECRETS_RULE_IDS]


# ---------------------------------------------------------------------------
# Clean source templates
#
# Each template is a complete, valid Python snippet that is "clean" with
# respect to all five secrets rules:
#
#   MCP010 — no string literal assigned to api_key/apikey/token/secret variable
#   MCP011 — no string literal assigned to password/passwd variable
#   MCP012 — no http:// URL in auth/API context (only https:// or no URL at all)
#   MCP013 — no OAuth URL without code_challenge (either no OAuth URL, or has code_challenge)
#   MCP014 — no credential variable passed to print() or logging
# ---------------------------------------------------------------------------

_CLEAN_TEMPLATES = [
    # --- Credentials loaded from environment variables (not hardcoded) ---
    """\
import os

api_key = os.environ.get("API_KEY")
token = os.environ.get("TOKEN")
secret = os.environ.get("SECRET")
password = os.environ.get("DB_PASSWORD")
""",
    """\
import os

api_key = os.getenv("API_KEY", "")
token = os.getenv("AUTH_TOKEN")
""",
    # --- HTTPS URLs in auth context (not http://) ---
    """\
auth_url = "https://auth.example.com/oauth/token"
api_url = "https://api.example.com/v1"
base_url = "https://service.example.com"
""",
    """\
endpoint = "https://api.example.com/endpoint"
host = "https://host.example.com"
""",
    # --- OAuth URL with code_challenge (PKCE present) ---
    """\
code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
auth_url = "https://auth.example.com/oauth/authorize?code_challenge=" + code_challenge
""",
    """\
client_id = "my-client"
challenge = "abc123"
auth_url = f"https://auth.example.com/oauth/authorize?client_id={client_id}&code_challenge={challenge}"
""",
    # --- Non-credential variables printed (not credential names) ---
    """\
username = "alice"
status = "active"
print(username, status)
""",
    """\
import logging
name = "service"
logging.info(name)
""",
    # --- MCP tool handlers with no secrets issues ---
    """\
import os

@mcp.tool()
def get_data(query: str) -> str:
    api_key = os.environ.get("API_KEY")
    return f"result for {query}"
""",
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
    # --- HTTP calls with https:// URLs ---
    """\
import httpx

@mcp.tool()
def fetch(query: str) -> str:
    result = httpx.get("https://api.example.com/search", timeout=10)
    return result.text
""",
    """\
import requests

@mcp.tool()
def submit(data: str) -> str:
    result = requests.post("https://api.example.com/submit", timeout=5)
    return result.text
""",
    # --- Variables with non-credential names assigned string literals ---
    """\
username = "alice"
greeting = "hello world"
description = "this is a description"
label = "my-label"
""",
    """\
name = "service-name"
version = "1.0.0"
region = "us-east-1"
""",
    # --- Empty module ---
    """\
""",
    # --- Module with only imports ---
    """\
import os
import sys
from pathlib import Path
""",
    # --- Module with only functions (no credential patterns) ---
    """\
def compute(x: int, y: int) -> int:
    return x + y

def format_message(msg: str) -> str:
    return f"[INFO] {msg}"
""",
    # --- Class with non-credential attributes ---
    """\
class Config:
    host = "localhost"
    port = 8080
    debug = False
    name = "my-service"
""",
    # --- Logging non-credential variables ---
    """\
import logging

logger = logging.getLogger(__name__)

def process(data: str) -> str:
    logger.info(data)
    return data.upper()
""",
    # --- Print non-credential variables ---
    """\
def display(message: str) -> None:
    print(message)
    print("Done")
""",
    # --- Multiple clean MCP tools ---
    """\
import os
import httpx

@mcp.tool()
def fetch_data(query: str) -> str:
    return httpx.get("https://api.example.com/data", timeout=30).text

@mcp.tool()
def get_config(section: str) -> str:
    return os.environ.get(f"CONFIG_{section.upper()}", "")

@mcp.tool()
def echo(message: str) -> str:
    return message
""",
    # --- http:// URL assigned to non-auth variable name ---
    # Note: variable names must NOT contain auth-context substrings
    # (auth, api, endpoint, url, base_url, host, server, connection, client)
    # to avoid triggering MCP012
    """\
documentation_link = "http://docs.example.com"
readme_page = "http://readme.example.com"
""",
    # --- Credential-like variable names but assigned non-string values ---
    """\
import os

api_key = None
token = 0
secret = []
password = {}
""",
    # --- Credential-like variable names assigned from function calls ---
    """\
import getpass
import os

password = getpass.getpass("Enter password: ")
api_key = input("Enter API key: ")
token = os.environ.get("TOKEN")
""",
]


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Strategy: sample from the pre-written clean templates
clean_template_strategy = st.sampled_from(_CLEAN_TEMPLATES)

# Strategy: generate a clean variable assignment with a non-credential name
# and a non-empty string value
_NON_CREDENTIAL_NAMES = [
    "username", "name", "label", "description", "title", "message",
    "region", "version", "host_name", "service_name", "app_name",
    "output", "result", "data", "content", "text", "value",
    "status", "mode", "format", "encoding", "language", "locale",
]

_SAFE_STRING_VALUES = [
    '"hello"',
    '"world"',
    '"example"',
    '"localhost"',
    '"us-east-1"',
    '"1.0.0"',
    '"active"',
    '"enabled"',
    '"production"',
    '"development"',
]


@st.composite
def clean_variable_assignment_snippet(draw) -> str:
    """Generate a clean variable assignment with a non-credential name."""
    var_name = draw(st.sampled_from(_NON_CREDENTIAL_NAMES))
    value = draw(st.sampled_from(_SAFE_STRING_VALUES))
    return f"{var_name} = {value}\n"


@st.composite
def clean_https_url_snippet(draw) -> str:
    """Generate a clean snippet with an https:// URL in an auth-related variable.

    Paths must NOT contain 'authorize' or 'authorization' to avoid triggering
    MCP013 (OAuth URL without code_challenge).
    """
    # Auth-related variable names that would trigger MCP012 if http:// were used
    auth_var = draw(st.sampled_from([
        "auth_url", "api_url", "base_url", "endpoint", "host",
        "server", "connection", "client_url",
    ]))
    # Paths that do NOT contain 'authorize' or 'authorization' (to avoid MCP013)
    path = draw(st.sampled_from([
        "oauth/token", "api/v1", "auth/login", "v2/endpoint",
        "token", "callback", "userinfo", "introspect",
    ]))
    return f'{auth_var} = "https://example.com/{path}"\n'


@st.composite
def clean_env_credential_snippet(draw) -> str:
    """Generate a clean snippet loading credentials from environment variables."""
    cred_var = draw(st.sampled_from([
        "api_key", "token", "secret", "password", "passwd",
        "apikey", "API_KEY", "TOKEN", "SECRET", "PASSWORD",
    ]))
    env_var = draw(st.sampled_from([
        "API_KEY", "TOKEN", "SECRET", "DB_PASSWORD", "AUTH_TOKEN",
        "SERVICE_SECRET", "APP_KEY",
    ]))
    return f'import os\n{cred_var} = os.environ.get("{env_var}")\n'


@st.composite
def clean_oauth_with_pkce_snippet(draw) -> str:
    """Generate a clean OAuth URL snippet that includes code_challenge."""
    challenge = draw(st.sampled_from([
        "abc123", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "challenge_value", "pkce_challenge",
    ]))
    return (
        f'code_challenge = "{challenge}"\n'
        f'auth_url = "https://auth.example.com/oauth/authorize?code_challenge=" + code_challenge\n'
    )


@st.composite
def clean_mcp_tool_snippet(draw) -> str:
    """Generate a clean MCP tool handler with no secrets issues."""
    body = draw(st.sampled_from([
        '    return f"Hello, {param}!"',
        "    return param.upper()",
        "    return len(param)",
        "    return param[::-1]",
        '    return "ok"',
        "    return param.strip()",
    ]))
    return (
        "@mcp.tool()\n"
        "def handler(param: str) -> str:\n"
        f"{body}\n"
    )


@st.composite
def clean_print_non_credential_snippet(draw) -> str:
    """Generate a clean snippet printing a non-credential variable."""
    var_name = draw(st.sampled_from(_NON_CREDENTIAL_NAMES))
    value = draw(st.sampled_from(_SAFE_STRING_VALUES))
    return f"{var_name} = {value}\nprint({var_name})\n"


# Combined strategy: pick from any clean source type
clean_source_strategy = st.one_of(
    clean_template_strategy,
    clean_variable_assignment_snippet(),
    clean_https_url_snippet(),
    clean_env_credential_snippet(),
    clean_oauth_with_pkce_snippet(),
    clean_mcp_tool_snippet(),
    clean_print_non_credential_snippet(),
)


# ---------------------------------------------------------------------------
# Property 4: Secrets rules produce no false positives on clean files
# ---------------------------------------------------------------------------


@settings(
    max_examples=25,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
@given(source=clean_source_strategy)
def test_secrets_rules_no_false_positives_on_clean_files(source: str) -> None:
    """Property 4: Secrets rules produce no false positives on clean files.

    For any Python source file that contains no string literals assigned to
    credential-named variables (api_key, token, password, etc.) and no http://
    URLs in auth contexts, the StaticAnalyzer SHALL emit zero findings for
    rules MCP010 through MCP014.

    # Feature: mcp-scan, Property 4: Secrets rules produce no false positives on clean files
    **Validates: Requirements 5.6**
    """
    # Ensure the generated source is valid Python (parseable)
    try:
        ast.parse(textwrap.dedent(source))
    except SyntaxError as exc:
        # If the generated source has a syntax error, skip this example
        # (the strategy should not produce invalid Python, but be defensive)
        pytest.skip(f"Generated source has syntax error: {exc}")

    findings = _check_all_secrets_rules(source)

    assert findings == [], (
        f"Expected zero findings for clean source, but got {len(findings)} finding(s):\n"
        + "\n".join(
            f"  [{f.rule_id}] {f.message} at {f.location}"
            for f in findings
        )
        + f"\n\nSource:\n{textwrap.dedent(source)}"
    )
