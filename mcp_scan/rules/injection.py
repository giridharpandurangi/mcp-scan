"""Tool description and prompt injection detection rules: MCP020–021."""

from __future__ import annotations

import ast
import re

from mcp_scan.models import Finding, Severity
from mcp_scan.rules import Rule
from mcp_scan.static.taint import _is_mcp_tool

# ---------------------------------------------------------------------------
# Shared patterns
# ---------------------------------------------------------------------------

# MCP021: prompt injection phrases
INJECTION_PATTERN = re.compile(
    r"ignore previous instructions|disregard|you are now|act as|system prompt",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_tool_description(func_def: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Extract the tool description string from an MCP tool function definition.

    Checks two sources in order:
    1. The ``description=`` keyword argument in the ``@mcp.tool()`` decorator call.
    2. The function's docstring via ``ast.get_docstring()``.

    Returns the first non-empty description found, or None if neither is present.
    """
    # Check for description= kwarg in the decorator call
    for decorator in func_def.decorator_list:
        if isinstance(decorator, ast.Call):
            func = decorator.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "tool"
                and isinstance(func.value, ast.Name)
                and func.value.id in ("mcp", "server")
            ):
                for kw in decorator.keywords:
                    if kw.arg == "description" and isinstance(kw.value, ast.Constant):
                        value = kw.value.value
                        if isinstance(value, str) and value:
                            return value

    # Fall back to docstring
    docstring = ast.get_docstring(func_def)
    if docstring:
        return docstring

    return None


# ---------------------------------------------------------------------------
# MCP020 — Tool description contains Unicode code points > U+00FF
# ---------------------------------------------------------------------------


class Mcp020UnicodeDescriptionRule(Rule):
    """MCP020: Tool description contains Unicode characters outside Latin-1 (> U+00FF)."""

    rule_id = "MCP020"
    severity = Severity.HIGH
    cwe = "CWE-116"
    description = (
        "Tool description contains Unicode characters outside the Basic Latin and "
        "Latin-1 Supplement blocks (code points above U+00FF)"
    )
    remediation = (
        "Remove or replace non-Latin-1 Unicode characters from the tool description. "
        "Hidden Unicode characters (e.g. zero-width spaces, bidirectional overrides, "
        "or lookalike characters) may be used to smuggle prompt injection payloads."
    )

    def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _is_mcp_tool(node):
                continue

            description = _extract_tool_description(node)
            if description is None:
                continue

            for char in description:
                if ord(char) > 0xFF:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        target=source_path,
                        location=f"{source_path}:{node.lineno}",
                        message=(
                            f"Tool description for '{node.name}' contains a non-Latin-1 "
                            f"Unicode character: U+{ord(char):04X} ('{char}'). "
                            "Hidden Unicode may be used to smuggle prompt injection payloads."
                        ),
                        remediation=self.remediation,
                    ))
                    # One finding per tool (first offending character)
                    break

        return findings


# ---------------------------------------------------------------------------
# MCP021 — Tool description matches injection pattern
# ---------------------------------------------------------------------------


class Mcp021InjectionPhraseRule(Rule):
    """MCP021: Tool description contains a prompt injection phrase."""

    rule_id = "MCP021"
    severity = Severity.HIGH
    cwe = "CWE-77"
    description = (
        "Tool description contains a phrase associated with prompt injection attacks "
        "(e.g. 'ignore previous instructions', 'you are now', 'act as')"
    )
    remediation = (
        "Remove prompt injection phrases from the tool description. "
        "Tool descriptions should describe the tool's purpose and usage, "
        "not contain instructions that manipulate LLM behavior."
    )

    def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _is_mcp_tool(node):
                continue

            description = _extract_tool_description(node)
            if description is None:
                continue

            match = INJECTION_PATTERN.search(description)
            if match:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    target=source_path,
                    location=f"{source_path}:{node.lineno}",
                    message=(
                        f"Tool description for '{node.name}' contains a prompt injection "
                        f"phrase: '{match.group()}'. "
                        "This may be used to manipulate LLM behavior."
                    ),
                    remediation=self.remediation,
                ))

        return findings
