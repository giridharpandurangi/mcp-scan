"""Unit tests for Rule ABC and auto-discovery.

Task 2.1 — Requirements 2.6, 2.7

Tests cover:
- A concrete stub rule is discovered automatically without manual registration
- The returned list is sorted by rule_id
- The Rule ABC cannot be instantiated directly
- Concrete rules must implement check()
"""

from __future__ import annotations

import ast

import pytest

from mcp_scan.models import Finding, Severity
from mcp_scan.rules import Rule, discover_rules
from tests.conftest import make_stub_rule_class


# ---------------------------------------------------------------------------
# Rule ABC tests
# ---------------------------------------------------------------------------


class TestRuleABC:
    def test_rule_abc_cannot_be_instantiated_directly(self):
        """Rule is abstract — instantiating it directly must raise TypeError."""
        with pytest.raises(TypeError):
            Rule()  # type: ignore[abstract]

    def test_concrete_rule_without_check_cannot_be_instantiated(self):
        """A subclass that does not implement check() is still abstract."""

        class IncompleteRule(Rule):
            rule_id = "MCP999"
            severity = Severity.INFO
            cwe = "CWE-000"
            description = "Incomplete"
            remediation = "None"

        with pytest.raises(TypeError):
            IncompleteRule()

    def test_concrete_rule_with_check_can_be_instantiated(self):
        """A subclass that implements check() can be instantiated."""

        class CompleteRule(Rule):
            rule_id = "MCP998"
            severity = Severity.LOW
            cwe = "CWE-000"
            description = "Complete stub"
            remediation = "None"

            def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
                return []

        rule = CompleteRule()
        assert isinstance(rule, Rule)
        assert rule.rule_id == "MCP998"

    def test_check_returns_list_of_findings(self):
        """check() must return a list; an empty list is valid."""

        class NoOpRule(Rule):
            rule_id = "MCP997"
            severity = Severity.INFO
            cwe = "CWE-000"
            description = "No-op"
            remediation = "None"

            def check(self, tree: ast.AST, source_path: str) -> list[Finding]:
                return []

        rule = NoOpRule()
        tree = ast.parse("x = 1")
        result = rule.check(tree, "dummy.py")
        assert isinstance(result, list)
        assert result == []


# ---------------------------------------------------------------------------
# Auto-discovery tests
# ---------------------------------------------------------------------------


class TestDiscoverRules:
    def test_discover_rules_returns_list(self):
        """discover_rules() must always return a list."""
        rules = discover_rules()
        assert isinstance(rules, list)

    def test_discover_rules_all_are_rule_instances(self):
        """Every returned object must be a concrete Rule instance."""
        for rule in discover_rules():
            assert isinstance(rule, Rule)

    def test_discover_rules_sorted_by_rule_id(self):
        """Returned rules must be sorted ascending by rule_id."""
        rules = discover_rules()
        ids = [r.rule_id for r in rules]
        assert ids == sorted(ids), f"Rules not sorted: {ids}"

    def test_stub_rule_in_injected_module_is_discovered(self, inject_rule_modules):
        """A concrete Rule subclass placed in a mcp_scan.rules.* module is
        discovered automatically — no manual registration required.
        """
        inject_rule_modules({"_test_stub_auto": "MCP_STUB_AUTO"})

        rules = discover_rules()
        rule_ids = [r.rule_id for r in rules]
        assert "MCP_STUB_AUTO" in rule_ids, (
            f"Stub rule was not auto-discovered. Found rule IDs: {rule_ids}"
        )

    def test_two_stub_rules_discovered_and_sorted(self, inject_rule_modules):
        """When two stub rules exist in injected modules, both are discovered
        and the returned list is sorted by rule_id.

        Modules are injected in Z-before-A order to confirm that sorting is
        actually applied rather than relying on insertion order.
        """
        # Inject Z first, then A — discovery must still return A before Z
        inject_rule_modules({"_test_stub_z": "MCP_Z", "_test_stub_a": "MCP_A"})

        rules = discover_rules()
        rule_ids = [r.rule_id for r in rules]

        assert "MCP_A" in rule_ids
        assert "MCP_Z" in rule_ids
        assert rule_ids == sorted(rule_ids), f"Rules not sorted: {rule_ids}"

        idx_a = rule_ids.index("MCP_A")
        idx_z = rule_ids.index("MCP_Z")
        assert idx_a < idx_z, "MCP_A should sort before MCP_Z"

    def test_abstract_rule_subclass_not_discovered(self, inject_rule_modules, monkeypatch):
        """An abstract intermediate subclass (still has unimplemented methods)
        must not appear in the discovered list.
        """
        import pkgutil
        import sys
        import types
        import mcp_scan.rules as rules_pkg

        stub_module_name = "mcp_scan.rules._test_stub_abstract"

        # This subclass does NOT implement check() — still abstract
        class AbstractIntermediate(Rule):
            rule_id = "MCP_ABSTRACT"
            severity = Severity.INFO
            cwe = "CWE-000"
            description = "Abstract intermediate"
            remediation = "None"
            # check() intentionally not implemented

        AbstractIntermediate.__module__ = stub_module_name

        stub_module = types.ModuleType(stub_module_name)
        stub_module.AbstractIntermediate = AbstractIntermediate  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, stub_module_name, stub_module)

        rules_path = list(rules_pkg.__path__)
        original_iter_modules = pkgutil.iter_modules

        def patched_iter_modules(path=None, prefix=""):
            yield from original_iter_modules(path, prefix)
            if path is not None and list(path) == rules_path:
                yield pkgutil.ModuleInfo(None, "_test_stub_abstract", False)

        monkeypatch.setattr(pkgutil, "iter_modules", patched_iter_modules)

        rules = discover_rules()
        rule_ids = [r.rule_id for r in rules]
        assert "MCP_ABSTRACT" not in rule_ids, (
            "Abstract rule subclass must not be included in discovered rules"
        )

    def test_duplicate_rule_class_not_returned_twice(self, inject_rule_modules, monkeypatch):
        """If the same Rule class is reachable via two modules (e.g., re-exported),
        discover_rules() must deduplicate and return it only once.
        """
        import pkgutil
        import sys
        import types
        import mcp_scan.rules as rules_pkg

        stub_mod_1 = "mcp_scan.rules._test_stub_dup1"
        stub_mod_2 = "mcp_scan.rules._test_stub_dup2"

        # Single class object registered under two module names
        SharedRule = make_stub_rule_class("MCP_DUP", stub_mod_1)

        mod1 = types.ModuleType(stub_mod_1)
        mod1.SharedRule = SharedRule  # type: ignore[attr-defined]
        mod2 = types.ModuleType(stub_mod_2)
        mod2.SharedRule = SharedRule  # type: ignore[attr-defined]  # same class object

        monkeypatch.setitem(sys.modules, stub_mod_1, mod1)
        monkeypatch.setitem(sys.modules, stub_mod_2, mod2)

        rules_path = list(rules_pkg.__path__)
        original_iter_modules = pkgutil.iter_modules

        def patched_iter_modules(path=None, prefix=""):
            yield from original_iter_modules(path, prefix)
            if path is not None and list(path) == rules_path:
                yield pkgutil.ModuleInfo(None, "_test_stub_dup1", False)
                yield pkgutil.ModuleInfo(None, "_test_stub_dup2", False)

        monkeypatch.setattr(pkgutil, "iter_modules", patched_iter_modules)

        rules = discover_rules()
        dup_rules = [r for r in rules if r.rule_id == "MCP_DUP"]
        assert len(dup_rules) == 1, (
            f"Expected exactly one instance of MCP_DUP, got {len(dup_rules)}"
        )
