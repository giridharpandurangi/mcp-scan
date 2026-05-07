"""Rule ABC and auto-discovery for mcp-scan detection rules."""

from __future__ import annotations

import ast
import importlib
import inspect
import pkgutil
from abc import ABC, abstractmethod

from mcp_scan.models import Finding, Severity


class Rule(ABC):
    """Abstract base class for all mcp-scan detection rules."""

    rule_id: str  # e.g. "MCP001"
    severity: Severity
    cwe: str  # e.g. "CWE-918"
    description: str
    remediation: str

    @abstractmethod
    def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
        """Apply this rule to a parsed AST. Return zero or more findings."""
        ...


def discover_rules() -> list[Rule]:
    """Auto-discover all concrete Rule subclasses from the mcp_scan.rules package.

    Returns rules sorted by rule_id for deterministic dispatch order.
    """
    import mcp_scan.rules as rules_pkg

    rule_classes: list[type[Rule]] = []

    for _finder, module_name, _is_pkg in pkgutil.iter_modules(rules_pkg.__path__):
        full_name = f"mcp_scan.rules.{module_name}"
        module = importlib.import_module(full_name)
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, Rule)
                and obj is not Rule
                and not inspect.isabstract(obj)
            ):
                rule_classes.append(obj)

    # Deduplicate (a class may be imported in multiple modules)
    seen: set[type[Rule]] = set()
    unique: list[type[Rule]] = []
    for cls in rule_classes:
        if cls not in seen:
            seen.add(cls)
            unique.append(cls)

    # Sort by rule_id for deterministic dispatch order
    unique.sort(key=lambda cls: cls.rule_id)

    return [cls() for cls in unique]
