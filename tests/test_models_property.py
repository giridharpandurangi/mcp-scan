"""Property-based tests for mcp_scan data models and taint sanitization.

# Feature: mcp-scan, Property 1: ScanResult JSON round-trip
# Feature: mcp-scan, Property 7: Taint sanitization suppresses findings

**Validates: Requirements 1.4, 9.7, 13.6, 3.4**
"""

from __future__ import annotations

import ast
import textwrap
from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from mcp_scan.models import Finding, ScanResult, Severity
from mcp_scan.static.taint import TaintTracker, _is_mcp_tool

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

severity_strategy: SearchStrategy[Severity] = st.sampled_from(list(Severity))

confidence_strategy: SearchStrategy[str] = st.sampled_from(["HIGH", "LOW"])

finding_strategy: SearchStrategy[Finding] = st.builds(
    Finding,
    rule_id=st.from_regex(r"MCP\d{3}", fullmatch=True),
    severity=severity_strategy,
    target=st.text(min_size=1, max_size=200),
    location=st.text(min_size=1, max_size=200),
    message=st.text(min_size=1, max_size=500),
    remediation=st.text(min_size=1, max_size=500),
    confidence=confidence_strategy,
)

scan_mode_strategy: SearchStrategy[str] = st.sampled_from(["static", "dynamic", "all"])

# Use Hypothesis's built-in datetime strategy; restrict to UTC-aware datetimes
# so that round-trip serialization is unambiguous.
timestamp_strategy = st.datetimes(
    min_value=datetime(2000, 1, 1),
    max_value=datetime(2099, 12, 31),
    timezones=st.just(timezone.utc),
)

scan_result_strategy: SearchStrategy[ScanResult] = st.builds(
    ScanResult,
    findings=st.lists(finding_strategy, min_size=0, max_size=10),
    scan_mode=scan_mode_strategy,
    target=st.text(min_size=1, max_size=200),
    timestamp=timestamp_strategy,
    tool_version=st.from_regex(r"\d+\.\d+\.\d+", fullmatch=True),
)


# ---------------------------------------------------------------------------
# Property 1: ScanResult JSON round-trip
# ---------------------------------------------------------------------------


@settings(max_examples=25)
@given(result=scan_result_strategy)
def test_scan_result_json_round_trip(result: ScanResult) -> None:
    """Property 1: ScanResult JSON round-trip.

    For any valid ScanResult object, serializing to JSON and deserializing back
    SHALL produce an equivalent ScanResult with identical field values.

    # Feature: mcp-scan, Property 1: ScanResult JSON round-trip
    **Validates: Requirements 1.4, 9.7, 13.6**
    """
    json_str = result.model_dump_json()
    restored = ScanResult.model_validate_json(json_str)
    assert restored == result


# ---------------------------------------------------------------------------
# Property 7: Taint sanitization suppresses findings
# ---------------------------------------------------------------------------
#
# Strategy: generate Python source code for MCP tool handlers where a tainted
# parameter is validated via one of the four recognized sanitization patterns
# before being passed to a dangerous sink.  After visiting the function body
# with TaintTracker, the sink argument must NOT be tainted — i.e. the
# sanitization correctly suppresses the taint flow.
#
# The four sanitization patterns tested:
#   1. re.match / re.fullmatch
#   2. explicit membership test  (x in ALLOWED_VALUES)
#   3. urlparse(...).hostname in ALLOWED_HOSTS
#   4. trusted_validators list   (custom validator function name)
#
# Because MCP001–005 rules are not yet implemented (task 6), we validate the
# property at the TaintTracker level: for each generated sanitized source, we
# assert that the variable holding the sanitized value is not tainted.
#
# Feature: mcp-scan, Property 7: Taint sanitization suppresses findings
# Validates: Requirements 3.4

# ---------------------------------------------------------------------------
# Helpers for source-code generation
# ---------------------------------------------------------------------------

# Safe identifiers for parameter and variable names
_SAFE_IDENTS = st.sampled_from(
    ["url", "path", "host", "endpoint", "target", "resource", "addr", "loc"]
)

# Sink call templates — each takes (param, var) where `var` is the sanitized
# variable name that should be passed to the sink.
# No leading spaces — indentation is added by the source-building helpers.
_SINK_TEMPLATES = [
    # MCP001 — httpx / requests
    "httpx.get({var})",
    "requests.get({var})",
    "httpx.post({var})",
    # MCP003 — urllib.request.urlopen
    "urllib.request.urlopen({var})",
    # MCP004 — subprocess with shell=True (uses the var as the command)
    "subprocess.run({var}, shell=True)",
    # MCP005 — open()
    "open({var})",
]

sink_template_strategy = st.sampled_from(_SINK_TEMPLATES)


def _build_re_match_source(param: str, sink_tpl: str) -> tuple[str, str, set[str]]:
    """Return (source, sanitized_var, tainted_params) for re.match sanitization."""
    sanitized_var = f"safe_{param}"
    sink_call = sink_tpl.format(var=sanitized_var)
    source = textwrap.dedent(f"""\
        @mcp.tool()
        def handler({param}):
            {sanitized_var} = re.match(r'^https://', {param})
            {sink_call}
    """)
    return source, sanitized_var, {param}


def _build_membership_source(param: str, sink_tpl: str) -> tuple[str, str, set[str]]:
    """Return (source, sanitized_var, tainted_params) for membership-test sanitization."""
    # Inside the if-body, `param` itself is sanitized; we assign it to a new var
    # so we can check that new var is not tainted.
    inner_var = f"checked_{param}"
    sink_call = sink_tpl.format(var=inner_var)
    source = textwrap.dedent(f"""\
        @mcp.tool()
        def handler({param}):
            if {param} in ALLOWED_VALUES:
                {inner_var} = {param}
                {sink_call}
    """)
    return source, inner_var, {param}


def _build_urlparse_source(param: str, sink_tpl: str) -> tuple[str, str, set[str]]:
    """Return (source, sanitized_var, tainted_params) for urlparse hostname sanitization."""
    inner_var = f"checked_{param}"
    sink_call = sink_tpl.format(var=inner_var)
    source = textwrap.dedent(f"""\
        @mcp.tool()
        def handler({param}):
            if urlparse({param}).hostname in ALLOWED_HOSTS:
                {inner_var} = {param}
                {sink_call}
    """)
    return source, inner_var, {param}


def _build_trusted_validator_source(
    param: str, sink_tpl: str, validator_name: str
) -> tuple[str, str, set[str]]:
    """Return (source, sanitized_var, tainted_params) for trusted_validator sanitization."""
    sanitized_var = f"safe_{param}"
    sink_call = sink_tpl.format(var=sanitized_var)
    source = textwrap.dedent(f"""\
        @mcp.tool()
        def handler({param}):
            {sanitized_var} = {validator_name}({param})
            {sink_call}
    """)
    return source, sanitized_var, {param}


# ---------------------------------------------------------------------------
# Strategies that produce (source, sanitized_var, tainted_params, kwargs)
# ---------------------------------------------------------------------------

_VALIDATOR_NAMES = st.sampled_from(
    ["validate_url", "is_safe_path", "check_host", "sanitize_input", "verify_endpoint"]
)


@st.composite
def re_match_sanitized_source(draw) -> tuple[str, str, set[str], dict]:
    param = draw(_SAFE_IDENTS)
    sink_tpl = draw(sink_template_strategy)
    source, sanitized_var, tainted_params = _build_re_match_source(param, sink_tpl)
    return source, sanitized_var, tainted_params, {}


@st.composite
def membership_sanitized_source(draw) -> tuple[str, str, set[str], dict]:
    param = draw(_SAFE_IDENTS)
    sink_tpl = draw(sink_template_strategy)
    source, sanitized_var, tainted_params = _build_membership_source(param, sink_tpl)
    return source, sanitized_var, tainted_params, {}


@st.composite
def urlparse_sanitized_source(draw) -> tuple[str, str, set[str], dict]:
    param = draw(_SAFE_IDENTS)
    sink_tpl = draw(sink_template_strategy)
    source, sanitized_var, tainted_params = _build_urlparse_source(param, sink_tpl)
    return source, sanitized_var, tainted_params, {}


@st.composite
def trusted_validator_sanitized_source(draw) -> tuple[str, str, set[str], dict]:
    param = draw(_SAFE_IDENTS)
    sink_tpl = draw(sink_template_strategy)
    validator_name = draw(_VALIDATOR_NAMES)
    source, sanitized_var, tainted_params = _build_trusted_validator_source(
        param, sink_tpl, validator_name
    )
    return source, sanitized_var, tainted_params, {"trusted_validators": [validator_name]}


# Combined strategy: pick any of the four sanitization patterns
sanitized_source_strategy = st.one_of(
    re_match_sanitized_source(),
    membership_sanitized_source(),
    urlparse_sanitized_source(),
    trusted_validator_sanitized_source(),
)


# ---------------------------------------------------------------------------
# Property 7 test
# ---------------------------------------------------------------------------


@settings(max_examples=25)
@given(case=sanitized_source_strategy)
def test_taint_sanitization_suppresses_findings(
    case: tuple[str, str, set[str], dict],
) -> None:
    """Property 7: Taint sanitization suppresses findings.

    For any Python source file where a tainted MCP tool parameter is validated
    against an allowlist (via re.match/re.fullmatch, explicit membership test,
    urlparse hostname check, or a trusted_validator) before being passed to a
    dangerous sink, the TaintTracker SHALL report the sanitized variable as NOT
    tainted — meaning no finding would be emitted for that taint flow.

    # Feature: mcp-scan, Property 7: Taint sanitization suppresses findings
    **Validates: Requirements 3.4**
    """
    source, sanitized_var, tainted_params, tracker_kwargs = case

    # Parse the generated source
    tree = ast.parse(source)

    # Find the MCP tool handler function
    func_def = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_mcp_tool(node):
                func_def = node
                break

    assert func_def is not None, (
        f"No MCP tool handler found in generated source:\n{source}"
    )

    # Run the taint tracker over the function body
    tracker = TaintTracker(tainted_params, **tracker_kwargs)
    tracker.visit(func_def)

    # The sanitized variable must NOT be tainted — sanitization suppressed the flow
    sanitized_name_node = ast.Name(id=sanitized_var, ctx=ast.Load())
    assert not tracker.is_tainted(sanitized_name_node), (
        f"Sanitized variable '{sanitized_var}' is still tainted after sanitization.\n"
        f"Sanitization pattern should have cleared the taint.\n"
        f"Generated source:\n{source}"
    )
