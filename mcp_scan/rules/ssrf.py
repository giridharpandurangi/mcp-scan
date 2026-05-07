"""SSRF and request-side detection rules: MCP001–MCP005."""

from __future__ import annotations

import ast
from typing import Callable

from mcp_scan.models import Finding, Severity
from mcp_scan.rules import Rule
from mcp_scan.static.taint import TaintTracker, _is_mcp_tool, collect_field_validated_types

# ---------------------------------------------------------------------------
# Shared sink sets
# ---------------------------------------------------------------------------

# HTTP client sinks: (module, function) pairs
_HTTP_SINKS: frozenset[tuple[str, str]] = frozenset({
    ("httpx", "get"),
    ("httpx", "post"),
    ("httpx", "request"),
    ("httpx", "put"),
    ("httpx", "delete"),
    ("httpx", "patch"),
    ("requests", "get"),
    ("requests", "post"),
    ("requests", "request"),
    ("requests", "put"),
    ("requests", "delete"),
    ("requests", "patch"),
})

# urllib.request sinks
_URLLIB_SINKS: frozenset[tuple[str, str]] = frozenset({
    ("urllib.request", "urlopen"),
})

# subprocess sinks
_SUBPROCESS_SINKS: frozenset[tuple[str, str]] = frozenset({
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "Popen"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
})

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

AliasMap = dict[str, tuple[str, str]]


def _resolve_call(
    call: ast.Call,
    alias_map: AliasMap,
) -> tuple[str, str] | None:
    """Resolve a Call node to a (module, function) pair using the alias map.

    Handles:
    - ``httpx.get(url)``          → ("httpx", "get")
    - ``fetch(url)``              → ("httpx", "get")  [if fetch = httpx.get]
    - ``h.get(url)``              → ("httpx", "get")  [if h = httpx]
    - ``urllib.request.urlopen``  → ("urllib.request", "urlopen")
    - ``subprocess.run``          → ("subprocess", "run")
    """
    func = call.func

    if isinstance(func, ast.Attribute):
        attr_name = func.attr
        value = func.value

        # Two-level: urllib.request.urlopen or subprocess.run
        if isinstance(value, ast.Attribute):
            outer = value.value
            if isinstance(outer, ast.Name):
                module = f"{outer.id}.{value.attr}"
                return (module, attr_name)
            return None

        # One-level: httpx.get, h.get (where h is an alias for httpx)
        if isinstance(value, ast.Name):
            local_name = value.id
            if local_name in alias_map:
                resolved_module, _ = alias_map[local_name]
                return (resolved_module, attr_name)
            return (local_name, attr_name)

    elif isinstance(func, ast.Name):
        # Plain function call: fetch(url), urlopen(url), open(path)
        local_name = func.id
        if local_name in alias_map:
            resolved_module, resolved_func = alias_map[local_name]
            return (resolved_module, resolved_func)
        return (local_name, local_name)

    return None


def _get_positional_arg(call: ast.Call, index: int) -> ast.expr | None:
    """Return the positional argument at *index*, or None if not present."""
    if len(call.args) > index:
        return call.args[index]
    return None


def _has_timeout_kwarg(call: ast.Call) -> bool:
    """Return True if the call has a ``timeout`` keyword argument."""
    return any(kw.arg == "timeout" for kw in call.keywords)


def _has_shell_true(call: ast.Call) -> bool:
    """Return True if the call has ``shell=True``."""
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _iter_mcp_tools(
    tree: ast.AST,
) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Return all MCP tool handler function definitions in the tree."""
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and _is_mcp_tool(node)
    ]


# ---------------------------------------------------------------------------
# SinkCheckingTaintTracker — integrates sink detection into taint traversal
# ---------------------------------------------------------------------------

class SinkCheckingTaintTracker(TaintTracker):
    """Extends TaintTracker to check for dangerous sinks during traversal.

    By integrating sink detection into the visitor traversal (rather than
    running a separate ast.walk after visiting), sanitization scoping from
    visit_If is correctly respected: a sink inside an if-body where the
    tainted variable has been sanitized will not produce a finding.
    """

    def __init__(
        self,
        tainted_params: set[str],
        sink_checker: Callable[[ast.Call, "SinkCheckingTaintTracker"], Finding | None],
        trusted_validators: list[str] | None = None,
        field_validated_types: set[str] | None = None,
    ) -> None:
        super().__init__(tainted_params, trusted_validators, field_validated_types)
        self._sink_checker = sink_checker
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        """Check each Call node against the sink checker, then continue."""
        finding = self._sink_checker(node, self)
        if finding is not None:
            self.findings.append(finding)
        self.generic_visit(node)


def _run_sink_tracker(
    func_def: ast.FunctionDef | ast.AsyncFunctionDef,
    tree: ast.AST,
    sink_checker: Callable[[ast.Call, SinkCheckingTaintTracker], Finding | None],
    trusted_validators: list[str] | None = None,
) -> list[Finding]:
    """Build a SinkCheckingTaintTracker, visit the function, return findings."""
    tainted_params: set[str] = {arg.arg for arg in func_def.args.args}
    if func_def.args.vararg:
        tainted_params.add(func_def.args.vararg.arg)
    if func_def.args.kwarg:
        tainted_params.add(func_def.args.kwarg.arg)
    for arg in func_def.args.kwonlyargs:
        tainted_params.add(arg.arg)

    field_validated = collect_field_validated_types(tree)
    tracker = SinkCheckingTaintTracker(
        tainted_params,
        sink_checker,
        trusted_validators=trusted_validators,
        field_validated_types=field_validated,
    )
    tracker.visit(func_def)
    return tracker.findings


# ---------------------------------------------------------------------------
# MCP001 — Tainted URL passed to HTTP client (SSRF)
# ---------------------------------------------------------------------------


class Mcp001TaintedUrlRule(Rule):
    """MCP001: HTTP client call where the URL argument is tainted (SSRF)."""

    rule_id = "MCP001"
    severity = Severity.HIGH
    cwe = "CWE-918"
    description = "Tainted URL passed to HTTP client — potential SSRF"
    remediation = (
        "Validate the URL against an allowlist before passing it to an HTTP client. "
        "Use re.match, a membership test, or urlparse().hostname checks."
    )

    def check(
        self,
        tree: ast.AST,
        source_path: str,
        alias_map: AliasMap | None = None,
    ) -> list[Finding]:
        alias_map = alias_map or {}
        findings: list[Finding] = []

        def _check_sink(call: ast.Call, tracker: SinkCheckingTaintTracker) -> Finding | None:
            resolved = _resolve_call(call, alias_map)
            if resolved not in _HTTP_SINKS:
                return None
            # URL is first positional arg, or url= keyword
            url_arg = _get_positional_arg(call, 0)
            if url_arg is None:
                for kw in call.keywords:
                    if kw.arg == "url":
                        url_arg = kw.value
                        break
            # For httpx.request("GET", url) the method is arg[0], url is arg[1]
            # Also check arg[1] if arg[0] looks like an HTTP method string
            if url_arg is not None and isinstance(url_arg, ast.Constant) and isinstance(url_arg.value, str):
                # First arg is a literal string (likely HTTP method) — check second arg
                second = _get_positional_arg(call, 1)
                if second is not None:
                    url_arg = second
            if url_arg is not None and tracker.is_tainted(url_arg):
                return Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    target=source_path,
                    location=f"{source_path}:{call.lineno}",
                    message=(
                        "Tainted URL passed to HTTP client — potential SSRF. "
                        f"Sink: {resolved[0]}.{resolved[1]}"
                    ),
                    remediation=self.remediation,
                )
            # Also check url= keyword when first arg was a method string
            for kw in call.keywords:
                if kw.arg == "url" and tracker.is_tainted(kw.value):
                    return Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        target=source_path,
                        location=f"{source_path}:{call.lineno}",
                        message=(
                            "Tainted URL passed to HTTP client — potential SSRF. "
                            f"Sink: {resolved[0]}.{resolved[1]}"
                        ),
                        remediation=self.remediation,
                    )
            return None

        for func_def in _iter_mcp_tools(tree):
            findings.extend(_run_sink_tracker(func_def, tree, _check_sink))

        return findings


# ---------------------------------------------------------------------------
# MCP002 — HTTP client call missing timeout
# ---------------------------------------------------------------------------


class Mcp002MissingTimeoutRule(Rule):
    """MCP002: HTTP client call that does not specify a timeout argument."""

    rule_id = "MCP002"
    severity = Severity.LOW
    cwe = ""
    description = "HTTP client call missing timeout — potential hang"
    remediation = (
        "Always specify a timeout when making HTTP requests to prevent indefinite hangs. "
        "Example: httpx.get(url, timeout=10)"
    )

    def check(
        self,
        tree: ast.AST,
        source_path: str,
        alias_map: AliasMap | None = None,
    ) -> list[Finding]:
        alias_map = alias_map or {}
        findings: list[Finding] = []

        for func_def in _iter_mcp_tools(tree):
            for call in ast.walk(func_def):
                if not isinstance(call, ast.Call):
                    continue
                resolved = _resolve_call(call, alias_map)
                if resolved not in _HTTP_SINKS:
                    continue
                if not _has_timeout_kwarg(call):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        target=source_path,
                        location=f"{source_path}:{call.lineno}",
                        message=(
                            f"HTTP client call to {resolved[0]}.{resolved[1]} "
                            "is missing a timeout argument."
                        ),
                        remediation=self.remediation,
                    ))

        return findings


# ---------------------------------------------------------------------------
# MCP003 — Tainted URL passed to urllib.request.urlopen
# ---------------------------------------------------------------------------


class Mcp003UrllibUrlOpenRule(Rule):
    """MCP003: urllib.request.urlopen called with a tainted URL argument."""

    rule_id = "MCP003"
    severity = Severity.HIGH
    cwe = "CWE-918"
    description = "Tainted URL passed to urllib.request.urlopen — potential SSRF"
    remediation = (
        "Validate the URL against an allowlist before passing it to urlopen. "
        "Consider using httpx or requests with explicit timeout and allowlist validation."
    )

    def check(
        self,
        tree: ast.AST,
        source_path: str,
        alias_map: AliasMap | None = None,
    ) -> list[Finding]:
        alias_map = alias_map or {}
        findings: list[Finding] = []

        def _check_sink(call: ast.Call, tracker: SinkCheckingTaintTracker) -> Finding | None:
            resolved = _resolve_call(call, alias_map)
            if resolved not in _URLLIB_SINKS:
                return None
            url_arg = _get_positional_arg(call, 0)
            if url_arg is not None and tracker.is_tainted(url_arg):
                return Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    target=source_path,
                    location=f"{source_path}:{call.lineno}",
                    message="Tainted URL passed to urllib.request.urlopen — potential SSRF.",
                    remediation=self.remediation,
                )
            return None

        for func_def in _iter_mcp_tools(tree):
            findings.extend(_run_sink_tracker(func_def, tree, _check_sink))

        return findings


# ---------------------------------------------------------------------------
# MCP004 — subprocess with shell=True and tainted argument
# ---------------------------------------------------------------------------


class Mcp004SubprocessShellRule(Rule):
    """MCP004: subprocess call with shell=True and a tainted argument."""

    rule_id = "MCP004"
    severity = Severity.CRITICAL
    cwe = "CWE-78"
    description = "Tainted argument passed to subprocess with shell=True — command injection"
    remediation = (
        "Never pass tainted input to subprocess with shell=True. "
        "Use a list of arguments instead of a shell string, and validate all inputs."
    )

    def check(
        self,
        tree: ast.AST,
        source_path: str,
        alias_map: AliasMap | None = None,
    ) -> list[Finding]:
        alias_map = alias_map or {}
        findings: list[Finding] = []

        def _check_sink(call: ast.Call, tracker: SinkCheckingTaintTracker) -> Finding | None:
            resolved = _resolve_call(call, alias_map)
            if resolved not in _SUBPROCESS_SINKS:
                return None
            if not _has_shell_true(call):
                return None
            cmd_arg = _get_positional_arg(call, 0)
            if cmd_arg is not None and tracker.is_tainted(cmd_arg):
                return Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    target=source_path,
                    location=f"{source_path}:{call.lineno}",
                    message=(
                        "Tainted argument passed to subprocess with shell=True — "
                        "potential command injection."
                    ),
                    remediation=self.remediation,
                )
            return None

        for func_def in _iter_mcp_tools(tree):
            findings.extend(_run_sink_tracker(func_def, tree, _check_sink))

        return findings


# ---------------------------------------------------------------------------
# MCP005 — Tainted path passed to open()
# ---------------------------------------------------------------------------


class Mcp005TaintedOpenRule(Rule):
    """MCP005: open() called with a tainted path argument."""

    rule_id = "MCP005"
    severity = Severity.HIGH
    cwe = "CWE-22"
    description = "Tainted path passed to open() — potential path traversal"
    remediation = (
        "Validate and sanitize the file path before passing it to open(). "
        "Use os.path.realpath() and verify the resolved path is within an allowed directory."
    )

    def check(
        self,
        tree: ast.AST,
        source_path: str,
        alias_map: AliasMap | None = None,
    ) -> list[Finding]:
        alias_map = alias_map or {}
        findings: list[Finding] = []

        def _check_sink(call: ast.Call, tracker: SinkCheckingTaintTracker) -> Finding | None:
            func = call.func
            if not (isinstance(func, ast.Name) and func.id == "open"):
                return None
            path_arg = _get_positional_arg(call, 0)
            if path_arg is None:
                for kw in call.keywords:
                    if kw.arg == "file":
                        path_arg = kw.value
                        break
            if path_arg is not None and tracker.is_tainted(path_arg):
                return Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    target=source_path,
                    location=f"{source_path}:{call.lineno}",
                    message="Tainted path passed to open() — potential path traversal.",
                    remediation=self.remediation,
                )
            return None

        for func_def in _iter_mcp_tools(tree):
            findings.extend(_run_sink_tracker(func_def, tree, _check_sink))

        return findings
