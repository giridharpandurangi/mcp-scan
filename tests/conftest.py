"""Shared pytest fixtures for mcp-scan tests."""

from __future__ import annotations

import ast
import pkgutil
import sys
import types
from collections.abc import Callable

import pytest

import mcp_scan.rules as _rules_pkg
from mcp_scan.models import Finding, Severity
from mcp_scan.rules import Rule


@pytest.fixture
def make_finding():
    """Factory fixture that returns a valid Finding, with any field overridable."""

    def _factory(**overrides) -> Finding:
        defaults = dict(
            rule_id="MCP001",
            severity=Severity.HIGH,
            target="src/server.py",
            location="src/server.py:42",
            message="Tainted URL passed to HTTP client",
            remediation="Validate the URL against an allowlist.",
        )
        defaults.update(overrides)
        return Finding(**defaults)

    return _factory


# ---------------------------------------------------------------------------
# Rule injection helpers
# ---------------------------------------------------------------------------


def make_stub_rule_class(rule_id: str, module_name: str) -> type[Rule]:
    """Return a concrete Rule subclass with the given rule_id.

    ``check`` is defined *inside* the class body so that ``__abstractmethods__``
    is empty on the returned class.  Assigning ``check`` after class creation
    does **not** clear ``__abstractmethods__``, which would cause
    ``inspect.isabstract()`` to return ``True`` and ``discover_rules()`` to
    silently skip the class.

    Args:
        rule_id: The ``rule_id`` string to assign (e.g. ``"MCP_STUB"``).
        module_name: The fully-qualified module name to stamp on the class
            (e.g. ``"mcp_scan.rules._test_stub"``).  This must match the key
            used when registering the module in ``sys.modules``.
    """

    class StubRule(Rule):
        def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
            return []

    StubRule.rule_id = rule_id  # type: ignore[attr-defined]
    StubRule.severity = Severity.INFO  # type: ignore[attr-defined]
    StubRule.cwe = "CWE-000"  # type: ignore[attr-defined]
    StubRule.description = f"Stub rule {rule_id}"  # type: ignore[attr-defined]
    StubRule.remediation = "No remediation needed."  # type: ignore[attr-defined]
    StubRule.__name__ = f"StubRule_{rule_id}"
    StubRule.__qualname__ = f"StubRule_{rule_id}"
    StubRule.__module__ = module_name
    return StubRule


@pytest.fixture
def inject_rule_modules(monkeypatch):
    """Fixture that injects synthetic rule modules into the discovery machinery.

    Usage::

        def test_something(inject_rule_modules):
            StubA = inject_rule_modules({"_test_a": "MCP_A", "_test_z": "MCP_Z"})
            rules = discover_rules()
            assert "MCP_A" in [r.rule_id for r in rules]

    The fixture accepts a mapping of ``{short_module_name: rule_id}`` and:

    1. Creates a concrete ``Rule`` subclass for each entry via
       :func:`make_stub_rule_class`.
    2. Registers each module in ``sys.modules`` under
       ``mcp_scan.rules.<short_name>``.
    3. Patches ``pkgutil.iter_modules`` so that ``discover_rules()`` sees the
       injected modules alongside any real ones.

    All patches are reverted automatically by ``monkeypatch`` on teardown.

    Returns a ``dict[str, type[Rule]]`` mapping ``rule_id → class`` so callers
    can inspect the injected classes directly.
    """

    def _inject(modules: dict[str, str]) -> dict[str, type[Rule]]:
        """
        Args:
            modules: ``{short_module_name: rule_id}`` — e.g.
                ``{"_test_stub": "MCP_STUB"}``.

        Returns:
            ``{rule_id: StubRuleClass}``
        """
        rules_path = list(_rules_pkg.__path__)
        injected_names: list[str] = []
        result: dict[str, type[Rule]] = {}

        for short_name, rule_id in modules.items():
            full_name = f"mcp_scan.rules.{short_name}"
            cls = make_stub_rule_class(rule_id, full_name)
            mod = types.ModuleType(full_name)
            setattr(mod, cls.__name__, cls)
            monkeypatch.setitem(sys.modules, full_name, mod)
            injected_names.append(short_name)
            result[rule_id] = cls

        original_iter_modules = pkgutil.iter_modules

        def patched_iter_modules(path=None, prefix=""):
            yield from original_iter_modules(path, prefix)
            if path is not None and list(path) == rules_path:
                for name in injected_names:
                    yield pkgutil.ModuleInfo(None, name, False)

        monkeypatch.setattr(pkgutil, "iter_modules", patched_iter_modules)
        return result

    return _inject
