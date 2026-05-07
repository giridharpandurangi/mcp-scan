"""Secrets and auth misconfiguration detection rules: MCP010–014."""

from __future__ import annotations

import ast
import re

from mcp_scan.models import Finding, Severity
from mcp_scan.rules import Rule
from mcp_scan.static.taint import TaintTracker

# ---------------------------------------------------------------------------
# Shared patterns
# ---------------------------------------------------------------------------

# MCP010: api_key, apikey, token, secret (case-insensitive)
_API_KEY_PATTERN = re.compile(
    r"(api_?key|token|secret)",
    re.IGNORECASE,
)

# MCP011: password, passwd (case-insensitive)
_PASSWORD_PATTERN = re.compile(
    r"(password|passwd)",
    re.IGNORECASE,
)

# Combined credential pattern for MCP014 taint sources (MCP010 + MCP011 names)
_CREDENTIAL_PATTERN = re.compile(
    r"(api_?key|token|secret|password|passwd)",
    re.IGNORECASE,
)

# MCP012: auth/API context variable names
_AUTH_CONTEXT_PATTERN = re.compile(
    r"(auth|api|endpoint|url|base_url|host|server|connection|client)",
    re.IGNORECASE,
)

# HTTP client call modules for MCP012 context detection
_HTTP_CLIENT_MODULES = frozenset({
    "httpx", "requests", "urllib", "aiohttp", "http",
})

# OAuth/auth URL keywords for MCP013 — must contain authorize/authorization
# (not just "auth" or "oauth" alone, to avoid false positives on token endpoints)
_OAUTH_PATTERN = re.compile(
    r"(authorize|authorization)",
    re.IGNORECASE,
)

# Logging function names for MCP014
_LOGGING_FUNCS = frozenset({
    "debug", "info", "warning", "error", "critical", "exception", "log",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_nonempty_string_constant(node: ast.expr) -> bool:
    """Return True if node is a non-empty string constant."""
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and len(node.value) > 0
    )


def _node_contains_http_url(node: ast.expr) -> bool:
    """Return True if the node is a string constant starting with http://."""
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("http://")
    )


def _call_is_http_client(call: ast.Call) -> bool:
    """Return True if the call looks like an HTTP client call."""
    func = call.func
    if isinstance(func, ast.Attribute):
        # module.method(...)
        if isinstance(func.value, ast.Name):
            return func.value.id in _HTTP_CLIENT_MODULES
        # module.submodule.method(...)
        if isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
            return func.value.value.id in _HTTP_CLIENT_MODULES
    elif isinstance(func, ast.Name):
        return func.id in {"get", "post", "request", "urlopen", "fetch"}
    return False


def _string_contains_oauth(value: str) -> bool:
    """Return True if the string contains OAuth/auth URL keywords."""
    return bool(_OAUTH_PATTERN.search(value))


def _extract_string_from_node(node: ast.expr) -> str | None:
    """Extract a string value from a Constant, BinOp (concat), or JoinedStr node."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _extract_string_from_node(node.left)
        right = _extract_string_from_node(node.right)
        parts = []
        if left is not None:
            parts.append(left)
        if right is not None:
            parts.append(right)
        return "".join(parts) if parts else None
    if isinstance(node, ast.JoinedStr):
        # Collect literal parts of the f-string
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
        return "".join(parts) if parts else None
    return None


# ---------------------------------------------------------------------------
# MCP010 — Hardcoded API key / token / secret
# ---------------------------------------------------------------------------


class Mcp010HardcodedApiKeyRule(Rule):
    """MCP010: String literal assigned to api_key/apikey/token/secret variable."""

    rule_id = "MCP010"
    severity = Severity.CRITICAL
    cwe = "CWE-798"
    description = "Hardcoded API key, token, or secret in source code"
    remediation = (
        "Never hardcode credentials in source code. "
        "Use environment variables (os.environ) or a secrets manager instead."
    )

    def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not _is_nonempty_string_constant(node.value):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and _API_KEY_PATTERN.search(target.id):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        target=source_path,
                        location=f"{source_path}:{node.lineno}",
                        message=(
                            f"Hardcoded credential assigned to '{target.id}'. "
                            "Storing secrets as string literals exposes them in source control."
                        ),
                        remediation=self.remediation,
                    ))

        return findings


# ---------------------------------------------------------------------------
# MCP011 — Hardcoded password / passwd
# ---------------------------------------------------------------------------


class Mcp011HardcodedPasswordRule(Rule):
    """MCP011: String literal assigned to password/passwd variable."""

    rule_id = "MCP011"
    severity = Severity.CRITICAL
    cwe = "CWE-798"
    description = "Hardcoded password in source code"
    remediation = (
        "Never hardcode passwords in source code. "
        "Use environment variables (os.environ) or a secrets manager instead."
    )

    def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not _is_nonempty_string_constant(node.value):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and _PASSWORD_PATTERN.search(target.id):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        target=source_path,
                        location=f"{source_path}:{node.lineno}",
                        message=(
                            f"Hardcoded password assigned to '{target.id}'. "
                            "Storing passwords as string literals exposes them in source control."
                        ),
                        remediation=self.remediation,
                    ))

        return findings


# ---------------------------------------------------------------------------
# MCP012 — Insecure HTTP URL in auth/API context
# ---------------------------------------------------------------------------


class Mcp012InsecureHttpRule(Rule):
    """MCP012: http:// string literal in auth/API context."""

    rule_id = "MCP012"
    severity = Severity.MEDIUM
    cwe = "CWE-319"
    description = "Insecure HTTP URL used in authentication or API context"
    remediation = (
        "Use HTTPS instead of HTTP for all authentication and API communication "
        "to prevent credentials and tokens from being transmitted in plaintext."
    )

    def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            # Case 1: http:// string assigned to an auth-related variable name
            if isinstance(node, ast.Assign):
                if not _node_contains_http_url(node.value):
                    continue
                for target in node.targets:
                    if isinstance(target, ast.Name) and _AUTH_CONTEXT_PATTERN.search(target.id):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            target=source_path,
                            location=f"{source_path}:{node.lineno}",
                            message=(
                                f"Insecure HTTP URL assigned to '{target.id}'. "
                                "Use HTTPS to protect data in transit."
                            ),
                            remediation=self.remediation,
                        ))

            # Case 2: http:// string passed as argument to an HTTP client call
            elif isinstance(node, ast.Call) and _call_is_http_client(node):
                for arg in node.args:
                    if _node_contains_http_url(arg):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            target=source_path,
                            location=f"{source_path}:{node.lineno}",
                            message=(
                                "Insecure HTTP URL passed to HTTP client call. "
                                "Use HTTPS to protect data in transit."
                            ),
                            remediation=self.remediation,
                        ))
                        break
                else:
                    for kw in node.keywords:
                        if kw.arg in ("url", "base_url", "endpoint") and _node_contains_http_url(kw.value):
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                target=source_path,
                                location=f"{source_path}:{node.lineno}",
                                message=(
                                    "Insecure HTTP URL passed to HTTP client call. "
                                    "Use HTTPS to protect data in transit."
                                ),
                                remediation=self.remediation,
                            ))
                            break

        return findings


# ---------------------------------------------------------------------------
# MCP013 — OAuth URL construction without code_challenge (missing PKCE)
# ---------------------------------------------------------------------------


class Mcp013MissingPkceRule(Rule):
    """MCP013: OAuth URL construction without code_challenge parameter."""

    rule_id = "MCP013"
    severity = Severity.HIGH
    cwe = "CWE-287"
    description = "OAuth authorization URL constructed without PKCE code_challenge parameter"
    remediation = (
        "Add a code_challenge parameter to OAuth authorization URLs to implement PKCE "
        "(RFC 7636). This prevents authorization code interception attacks."
    )

    def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            # Look for assignments where the value is a string concat or f-string
            # containing oauth/authorize/auth keywords
            if isinstance(node, ast.Assign):
                url_str = _extract_string_from_node(node.value)
                if url_str is not None and _string_contains_oauth(url_str):
                    if "code_challenge" not in url_str:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            target=source_path,
                            location=f"{source_path}:{node.lineno}",
                            message=(
                                "OAuth authorization URL constructed without 'code_challenge' "
                                "parameter — PKCE is not implemented."
                            ),
                            remediation=self.remediation,
                        ))

            # Also look for f-strings or string concatenations used directly in calls
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                for arg in call.args:
                    url_str = _extract_string_from_node(arg)
                    if url_str is not None and _string_contains_oauth(url_str):
                        if "code_challenge" not in url_str:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                target=source_path,
                                location=f"{source_path}:{node.lineno}",
                                message=(
                                    "OAuth authorization URL constructed without 'code_challenge' "
                                    "parameter — PKCE is not implemented."
                                ),
                                remediation=self.remediation,
                            ))

        return findings


# ---------------------------------------------------------------------------
# MCP014 — Credential variable passed to print() or logging
# ---------------------------------------------------------------------------


class Mcp014CredentialLoggingRule(Rule):
    """MCP014: Tainted credential variable passed to print() or logging function."""

    rule_id = "MCP014"
    severity = Severity.HIGH
    cwe = "CWE-532"
    description = "Credential or token variable passed to print() or logging function"
    remediation = (
        "Never log or print credential variables. "
        "Remove the logging statement or redact the sensitive value before logging."
    )

    def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
        findings: list[Finding] = []

        # Collect credential variable names: those assigned string literals
        # matching the credential pattern (MCP010/011 sources)
        credential_vars: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if _is_nonempty_string_constant(node.value):
                    for target in node.targets:
                        if (
                            isinstance(target, ast.Name)
                            and _CREDENTIAL_PATTERN.search(target.id)
                        ):
                            credential_vars.add(target.id)

        if not credential_vars:
            return findings

        # Use TaintTracker to propagate taint from credential variables
        # Walk all function definitions (not just MCP tools) for this rule
        for func_def in ast.walk(tree):
            if not isinstance(func_def, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Seed taint with credential vars that are in scope (global or local)
            tracker = TaintTracker(tainted_params=credential_vars)
            tracker.visit(func_def)

            # Check all Call nodes in the function for print/logging sinks
            for call_node in ast.walk(func_def):
                if not isinstance(call_node, ast.Call):
                    continue

                func = call_node.func
                is_print = isinstance(func, ast.Name) and func.id == "print"
                is_logging = (
                    isinstance(func, ast.Attribute)
                    and func.attr in _LOGGING_FUNCS
                    and isinstance(func.value, ast.Name)
                    and func.value.id in ("logging", "logger", "log")
                )

                if not (is_print or is_logging):
                    continue

                # Check if any argument is a tainted credential variable
                for arg in call_node.args:
                    if tracker.is_tainted(arg):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            target=source_path,
                            location=f"{source_path}:{call_node.lineno}",
                            message=(
                                "Credential variable passed to "
                                f"{'print()' if is_print else 'logging function'} — "
                                "sensitive data may be exposed in logs."
                            ),
                            remediation=self.remediation,
                        ))
                        break

        # Also check module-level print/logging calls (outside functions)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # Skip calls inside function bodies (already handled above)
            func = node.func
            is_print = isinstance(func, ast.Name) and func.id == "print"
            is_logging = (
                isinstance(func, ast.Attribute)
                and func.attr in _LOGGING_FUNCS
                and isinstance(func.value, ast.Name)
                and func.value.id in ("logging", "logger", "log")
            )
            if not (is_print or is_logging):
                continue

            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in credential_vars:
                    # Check this isn't inside a function (already handled)
                    # We do a simple check: if the call is at module level
                    # This is a best-effort check for module-level credential logging
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        target=source_path,
                        location=f"{source_path}:{node.lineno}",
                        message=(
                            "Credential variable passed to "
                            f"{'print()' if is_print else 'logging function'} — "
                            "sensitive data may be exposed in logs."
                        ),
                        remediation=self.remediation,
                    ))
                    break

        # Deduplicate findings by location
        seen: set[str] = set()
        unique: list[Finding] = []
        for f in findings:
            key = f"{f.rule_id}:{f.location}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique
