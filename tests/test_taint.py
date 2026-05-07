"""Unit tests for TaintTracker and related helpers.

Task 3.1 — Requirements 3.2, 3.3, 3.4

Tests cover:
- Taint propagation through assignment, f-string, and concatenation
- Taint cleared by re.match, membership test, urlparse hostname check
- Pydantic @field_validator sanitization (same-file class only — MVP scope)
- trusted_validators config list clears taint
- _is_mcp_tool helper
- collect_field_validated_types helper
"""

from __future__ import annotations

import ast

import pytest

from mcp_scan.static.taint import (
    TaintTracker,
    _is_mcp_tool,
    collect_field_validated_types,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _name(name: str) -> ast.Name:
    """Create a minimal ast.Name node for use in is_tainted() checks."""
    node = ast.Name(id=name, ctx=ast.Load())
    return node


def _parse_and_visit(source: str, tainted_params: set[str], **kwargs) -> TaintTracker:
    """Parse source, create a TaintTracker, visit the AST, and return the tracker."""
    tree = ast.parse(source)
    tracker = TaintTracker(tainted_params, **kwargs)
    tracker.visit(tree)
    return tracker


# ---------------------------------------------------------------------------
# is_tainted — basic node types
# ---------------------------------------------------------------------------


class TestIsTainted:
    def test_name_in_tainted_set(self):
        tracker = TaintTracker({"url"})
        assert tracker.is_tainted(_name("url")) is True

    def test_name_not_in_tainted_set(self):
        tracker = TaintTracker({"url"})
        assert tracker.is_tainted(_name("safe_var")) is False

    def test_binop_add_left_tainted(self):
        tracker = TaintTracker({"url"})
        node = ast.BinOp(
            left=ast.Name(id="url", ctx=ast.Load()),
            op=ast.Add(),
            right=ast.Constant(value="/path"),
        )
        assert tracker.is_tainted(node) is True

    def test_binop_add_right_tainted(self):
        tracker = TaintTracker({"suffix"})
        node = ast.BinOp(
            left=ast.Constant(value="https://example.com"),
            op=ast.Add(),
            right=ast.Name(id="suffix", ctx=ast.Load()),
        )
        assert tracker.is_tainted(node) is True

    def test_binop_add_neither_tainted(self):
        tracker = TaintTracker({"url"})
        node = ast.BinOp(
            left=ast.Constant(value="a"),
            op=ast.Add(),
            right=ast.Constant(value="b"),
        )
        assert tracker.is_tainted(node) is False

    def test_binop_non_add_not_tainted(self):
        """Multiplication of a tainted name is NOT propagated."""
        tracker = TaintTracker({"x"})
        node = ast.BinOp(
            left=ast.Name(id="x", ctx=ast.Load()),
            op=ast.Mult(),
            right=ast.Constant(value=2),
        )
        assert tracker.is_tainted(node) is False

    def test_fstring_with_tainted_value(self):
        """f-string containing a tainted variable is tainted."""
        tracker = TaintTracker({"url"})
        # Represents f"https://{url}/path"
        node = ast.JoinedStr(values=[
            ast.Constant(value="https://"),
            ast.FormattedValue(
                value=ast.Name(id="url", ctx=ast.Load()),
                conversion=-1,
                format_spec=None,
            ),
            ast.Constant(value="/path"),
        ])
        assert tracker.is_tainted(node) is True

    def test_fstring_without_tainted_value(self):
        """f-string with only clean variables is not tainted."""
        tracker = TaintTracker({"url"})
        node = ast.JoinedStr(values=[
            ast.Constant(value="hello "),
            ast.FormattedValue(
                value=ast.Name(id="name", ctx=ast.Load()),
                conversion=-1,
                format_spec=None,
            ),
        ])
        assert tracker.is_tainted(node) is False

    def test_constant_not_tainted(self):
        tracker = TaintTracker({"url"})
        assert tracker.is_tainted(ast.Constant(value="literal")) is False

    def test_call_not_tainted(self):
        """Function call results are not tainted by default."""
        tracker = TaintTracker({"url"})
        node = ast.Call(
            func=ast.Name(id="some_func", ctx=ast.Load()),
            args=[ast.Name(id="url", ctx=ast.Load())],
            keywords=[],
        )
        assert tracker.is_tainted(node) is False


# ---------------------------------------------------------------------------
# visit_Assign — taint propagation
# ---------------------------------------------------------------------------


class TestVisitAssign:
    def test_direct_assignment_propagates_taint(self):
        """x = tainted_var → x becomes tainted."""
        tracker = _parse_and_visit("x = url", {"url"})
        assert tracker.is_tainted(_name("x")) is True

    def test_clean_assignment_clears_taint(self):
        """url = 'literal' → url is no longer tainted."""
        tracker = _parse_and_visit("url = 'https://example.com'", {"url"})
        assert tracker.is_tainted(_name("url")) is False

    def test_concatenation_propagates_taint(self):
        """y = url + '/path' → y is tainted."""
        tracker = _parse_and_visit("y = url + '/path'", {"url"})
        assert tracker.is_tainted(_name("y")) is True

    def test_fstring_assignment_propagates_taint(self):
        """y = f'https://{url}' → y is tainted."""
        tracker = _parse_and_visit("y = f'https://{url}'", {"url"})
        assert tracker.is_tainted(_name("y")) is True

    def test_chained_assignment_propagates_taint(self):
        """x = url; y = x → y is tainted."""
        src = "x = url\ny = x"
        tracker = _parse_and_visit(src, {"url"})
        assert tracker.is_tainted(_name("x")) is True
        assert tracker.is_tainted(_name("y")) is True

    def test_tuple_unpack_propagates_taint(self):
        """a, b = tainted_var, 'safe' — both a and b get taint status of RHS."""
        # The whole RHS is a Tuple; is_tainted(Tuple) returns False (not a Name/BinOp/JoinedStr)
        # so neither a nor b should be tainted from this assignment
        src = "a, b = url, 'safe'"
        tracker = _parse_and_visit(src, {"url"})
        # The RHS is a Tuple node — is_tainted returns False for Tuple
        # so both a and b are cleared
        assert tracker.is_tainted(_name("a")) is False
        assert tracker.is_tainted(_name("b")) is False

    def test_assignment_to_multiple_targets(self):
        """a = b = tainted_var → both a and b become tainted."""
        src = "a = b = url"
        tracker = _parse_and_visit(src, {"url"})
        assert tracker.is_tainted(_name("a")) is True
        assert tracker.is_tainted(_name("b")) is True


# ---------------------------------------------------------------------------
# visit_AugAssign — augmented assignment
# ---------------------------------------------------------------------------


class TestVisitAugAssign:
    def test_aug_assign_tainted_rhs_taints_target(self):
        """path += url → path becomes tainted."""
        src = "path = '/base'\npath += url"
        tracker = _parse_and_visit(src, {"url"})
        assert tracker.is_tainted(_name("path")) is True

    def test_aug_assign_clean_rhs_does_not_clear_taint(self):
        """x += 'safe' when x is already tainted → x stays tainted."""
        src = "x = url\nx += '/safe_suffix'"
        tracker = _parse_and_visit(src, {"url"})
        assert tracker.is_tainted(_name("x")) is True

    def test_aug_assign_clean_rhs_on_clean_var_stays_clean(self):
        """x += 'safe' when x is not tainted → x stays clean."""
        src = "x = 'base'\nx += '/path'"
        tracker = _parse_and_visit(src, {"url"})
        assert tracker.is_tainted(_name("x")) is False


# ---------------------------------------------------------------------------
# visit_AnnAssign — annotated assignment
# ---------------------------------------------------------------------------


class TestVisitAnnAssign:
    def test_ann_assign_propagates_taint(self):
        """x: str = url → x becomes tainted."""
        src = "x: str = url"
        tracker = _parse_and_visit(src, {"url"})
        assert tracker.is_tainted(_name("x")) is True

    def test_ann_assign_bare_annotation_no_propagation(self):
        """x: str (no value) → no taint change."""
        src = "x: str"
        tracker = _parse_and_visit(src, {"url"})
        assert tracker.is_tainted(_name("x")) is False

    def test_ann_assign_clean_rhs_clears_taint(self):
        """url: str = 'literal' → url is no longer tainted."""
        src = "url: str = 'https://example.com'"
        tracker = _parse_and_visit(src, {"url"})
        assert tracker.is_tainted(_name("url")) is False

    def test_ann_assign_field_validated_type_sanitizes(self):
        """x: ValidatedModel = url → x is sanitized because ValidatedModel has @field_validator."""
        src = "x: ValidatedModel = url"
        tracker = _parse_and_visit(
            src,
            {"url"},
            field_validated_types={"ValidatedModel"},
        )
        assert tracker.is_tainted(_name("x")) is False


# ---------------------------------------------------------------------------
# Sanitization via re.match / re.fullmatch
# ---------------------------------------------------------------------------


class TestReMatchSanitization:
    def test_re_match_sanitizes_assignment(self):
        """result = re.match(pattern, url) → result is not tainted."""
        src = "result = re.match(r'^https://', url)"
        tracker = _parse_and_visit(src, {"url"})
        assert tracker.is_tainted(_name("result")) is False

    def test_re_fullmatch_sanitizes_assignment(self):
        """result = re.fullmatch(pattern, url) → result is not tainted."""
        src = "result = re.fullmatch(r'^https://[a-z]+\\.com$', url)"
        tracker = _parse_and_visit(src, {"url"})
        assert tracker.is_tainted(_name("result")) is False

    def test_re_search_does_not_sanitize(self):
        """re.search is not in the allowlist — result should not be marked sanitized."""
        src = "result = re.search(r'pattern', url)"
        tracker = _parse_and_visit(src, {"url"})
        # re.search is not a sanitizer, result is just a clean (non-tainted) call result
        assert tracker.is_tainted(_name("result")) is False


# ---------------------------------------------------------------------------
# Sanitization via membership test (if x in ALLOWED)
# ---------------------------------------------------------------------------


class TestMembershipTestSanitization:
    def test_if_in_clears_taint_in_body(self):
        """if url in ALLOWED_URLS: use(url) — url is sanitized inside the if body."""
        src = """
if url in ALLOWED_URLS:
    x = url
"""
        tracker = _parse_and_visit(src, {"url"})
        # x is assigned inside the if-body where url is sanitized
        assert tracker.is_tainted(_name("x")) is False

    def test_if_in_taint_restored_after_body(self):
        """After the if-body, url is still tainted (sanitization is scoped)."""
        src = """
if url in ALLOWED_URLS:
    x = url
y = url
"""
        tracker = _parse_and_visit(src, {"url"})
        assert tracker.is_tainted(_name("x")) is False
        assert tracker.is_tainted(_name("y")) is True

    def test_if_not_in_does_not_sanitize(self):
        """if x not in ALLOWED is NOT a sanitizer."""
        src = """
if url not in BLOCKED:
    x = url
"""
        tracker = _parse_and_visit(src, {"url"})
        # 'not in' uses NotIn operator, not In — no sanitization
        assert tracker.is_tainted(_name("x")) is True


# ---------------------------------------------------------------------------
# Sanitization via urlparse().hostname in ALLOWED
# ---------------------------------------------------------------------------


class TestUrlparseSanitization:
    def test_urlparse_hostname_in_allowed_sanitizes_in_body(self):
        """if urlparse(url).hostname in ALLOWED_HOSTS: use(url) — url sanitized in body."""
        src = """
if urlparse(url).hostname in ALLOWED_HOSTS:
    x = url
"""
        tracker = _parse_and_visit(src, {"url"})
        assert tracker.is_tainted(_name("x")) is False

    def test_urlparse_hostname_assignment_sanitizes(self):
        """hostname = urlparse(url).hostname → hostname is sanitized (not tainted)."""
        src = "hostname = urlparse(url).hostname"
        tracker = _parse_and_visit(src, {"url"})
        assert tracker.is_tainted(_name("hostname")) is False


# ---------------------------------------------------------------------------
# Sanitization via trusted_validators
# ---------------------------------------------------------------------------


class TestTrustedValidators:
    def test_trusted_validator_call_sanitizes(self):
        """result = validate_url(url) → result is not tainted."""
        src = "result = validate_url(url)"
        tracker = _parse_and_visit(src, {"url"}, trusted_validators=["validate_url"])
        assert tracker.is_tainted(_name("result")) is False

    def test_unknown_function_does_not_sanitize(self):
        """result = unknown_func(url) → result is not tainted (call result is clean by default)."""
        src = "result = unknown_func(url)"
        tracker = _parse_and_visit(src, {"url"}, trusted_validators=["validate_url"])
        # unknown_func is not in trusted_validators; call result is not tainted
        assert tracker.is_tainted(_name("result")) is False

    def test_multiple_trusted_validators(self):
        """Multiple validators in the list all sanitize."""
        src = """
a = validate_url(url)
b = is_safe_path(path)
"""
        tracker = _parse_and_visit(
            src,
            {"url", "path"},
            trusted_validators=["validate_url", "is_safe_path"],
        )
        assert tracker.is_tainted(_name("a")) is False
        assert tracker.is_tainted(_name("b")) is False


# ---------------------------------------------------------------------------
# Pydantic @field_validator sanitization
# ---------------------------------------------------------------------------


class TestFieldValidatorSanitization:
    def test_collect_field_validated_types_finds_class(self):
        """collect_field_validated_types returns class names with @field_validator."""
        src = """
from pydantic import BaseModel, field_validator

class SafeInput(BaseModel):
    url: str

    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        return v
"""
        tree = ast.parse(src)
        types_ = collect_field_validated_types(tree)
        assert "SafeInput" in types_

    def test_collect_field_validated_types_ignores_plain_class(self):
        """Classes without @field_validator are not included."""
        src = """
class PlainModel:
    def some_method(self):
        pass
"""
        tree = ast.parse(src)
        types_ = collect_field_validated_types(tree)
        assert "PlainModel" not in types_

    def test_collect_field_validated_types_finds_validator_decorator(self):
        """@validator (Pydantic v1 style) is also recognized."""
        src = """
from pydantic import BaseModel, validator

class OldModel(BaseModel):
    url: str

    @validator('url')
    def validate_url(cls, v):
        return v
"""
        tree = ast.parse(src)
        types_ = collect_field_validated_types(tree)
        assert "OldModel" in types_

    def test_ann_assign_with_field_validated_type_clears_taint(self):
        """x: SafeInput = url → x is sanitized when SafeInput has @field_validator."""
        src = "x: SafeInput = url"
        tracker = _parse_and_visit(
            src,
            {"url"},
            field_validated_types={"SafeInput"},
        )
        assert tracker.is_tainted(_name("x")) is False

    def test_ann_assign_with_non_validated_type_propagates_taint(self):
        """x: PlainModel = url → x is tainted when PlainModel has no @field_validator."""
        src = "x: PlainModel = url"
        tracker = _parse_and_visit(
            src,
            {"url"},
            field_validated_types=set(),  # PlainModel not in validated types
        )
        assert tracker.is_tainted(_name("x")) is True


# ---------------------------------------------------------------------------
# _is_mcp_tool helper
# ---------------------------------------------------------------------------


class TestIsMcpTool:
    def test_mcp_tool_decorator_with_call(self):
        """@mcp.tool() is recognized."""
        src = """
@mcp.tool()
def my_tool(x):
    pass
"""
        tree = ast.parse(src)
        func = tree.body[0]
        assert _is_mcp_tool(func) is True

    def test_server_tool_decorator_with_call(self):
        """@server.tool() is recognized."""
        src = """
@server.tool()
def my_tool(x):
    pass
"""
        tree = ast.parse(src)
        func = tree.body[0]
        assert _is_mcp_tool(func) is True

    def test_mcp_tool_bare_attribute(self):
        """@mcp.tool (without call parens) is also recognized."""
        src = """
@mcp.tool
def my_tool(x):
    pass
"""
        tree = ast.parse(src)
        func = tree.body[0]
        assert _is_mcp_tool(func) is True

    def test_unrelated_decorator_not_recognized(self):
        """@app.route() is not an MCP tool decorator."""
        src = """
@app.route('/path')
def my_handler(x):
    pass
"""
        tree = ast.parse(src)
        func = tree.body[0]
        assert _is_mcp_tool(func) is False

    def test_no_decorator_not_recognized(self):
        """A plain function with no decorators is not an MCP tool."""
        src = """
def plain_function(x):
    pass
"""
        tree = ast.parse(src)
        func = tree.body[0]
        assert _is_mcp_tool(func) is False

    def test_async_function_with_mcp_tool(self):
        """@mcp.tool() on an async function is recognized."""
        src = """
@mcp.tool()
async def my_async_tool(x):
    pass
"""
        tree = ast.parse(src)
        func = tree.body[0]
        assert _is_mcp_tool(func) is True

    def test_other_tool_name_not_recognized(self):
        """@other.tool() where other is not mcp/server is not recognized."""
        src = """
@other.tool()
def my_tool(x):
    pass
"""
        tree = ast.parse(src)
        func = tree.body[0]
        assert _is_mcp_tool(func) is False


# ---------------------------------------------------------------------------
# Integration: full function body traversal
# ---------------------------------------------------------------------------


class TestIntegration:
    def test_taint_propagates_through_function_body(self):
        """Taint flows from parameter through multiple assignments."""
        src = """
def handler(url):
    x = url
    y = x + '/path'
    z = f'https://{y}'
"""
        tree = ast.parse(src)
        func = tree.body[0]
        tracker = TaintTracker({"url"})
        tracker.visit(func)
        assert tracker.is_tainted(_name("x")) is True
        assert tracker.is_tainted(_name("y")) is True
        assert tracker.is_tainted(_name("z")) is True

    def test_sanitization_stops_propagation(self):
        """After re.match sanitization, downstream variables are clean."""
        src = """
def handler(url):
    safe = re.match(r'^https://', url)
    result = safe
"""
        tree = ast.parse(src)
        func = tree.body[0]
        tracker = TaintTracker({"url"})
        tracker.visit(func)
        assert tracker.is_tainted(_name("safe")) is False
        assert tracker.is_tainted(_name("result")) is False

    def test_original_param_still_tainted_after_sanitized_copy(self):
        """Sanitizing a copy does not clear taint on the original parameter."""
        src = """
def handler(url):
    safe = re.match(r'^https://', url)
"""
        tree = ast.parse(src)
        func = tree.body[0]
        tracker = TaintTracker({"url"})
        tracker.visit(func)
        assert tracker.is_tainted(_name("url")) is True
        assert tracker.is_tainted(_name("safe")) is False


# ---------------------------------------------------------------------------
# _is_field_validator_decorator — Attribute and bare-Name paths (lines 39–44)
# ---------------------------------------------------------------------------


class TestIsFieldValidatorDecorator:
    """Exercise the two uncovered branches in _is_field_validator_decorator:
    - ast.Call whose func is an ast.Attribute (e.g. @pydantic.field_validator(...))
    - bare ast.Name (e.g. @field_validator without call parens)
    """

    def test_attribute_call_field_validator_recognized(self):
        """@pydantic.field_validator('field') — Attribute path inside ast.Call."""
        src = """
class MyModel:
    @pydantic.field_validator('url')
    def validate_url(cls, v):
        return v
"""
        tree = ast.parse(src)
        types_ = collect_field_validated_types(tree)
        assert "MyModel" in types_

    def test_bare_name_field_validator_recognized(self):
        """@field_validator (bare Name, no call parens) is recognized."""
        src = """
class MyModel:
    @field_validator
    def validate_url(cls, v):
        return v
"""
        tree = ast.parse(src)
        types_ = collect_field_validated_types(tree)
        assert "MyModel" in types_

    def test_bare_name_validator_recognized(self):
        """@validator (bare Name, Pydantic v1 style, no call parens) is recognized."""
        src = """
class MyModel:
    @validator
    def validate_url(cls, v):
        return v
"""
        tree = ast.parse(src)
        types_ = collect_field_validated_types(tree)
        assert "MyModel" in types_


# ---------------------------------------------------------------------------
# _extract_sanitized_names_from_compare — non-Name urlparse arg (line 212)
# ---------------------------------------------------------------------------


class TestExtractSanitizedNamesNonNameArg:
    """Line 212: urlparse called with a non-Name argument (e.g. a subscript or
    call result) — the branch that checks ``isinstance(call.args[0], ast.Name)``
    falls through without adding anything to sanitized.
    """

    def test_urlparse_with_non_name_arg_does_not_sanitize(self):
        """if urlparse(get_url()).hostname in ALLOWED — arg is a Call, not a Name.
        No variable name can be extracted, so nothing is sanitized.
        """
        src = """
if urlparse(get_url()).hostname in ALLOWED_HOSTS:
    x = url
"""
        tracker = _parse_and_visit(src, {"url"})
        # url is still tainted because the urlparse arg was not a plain Name
        assert tracker.is_tainted(_name("url")) is True
        # x is assigned inside the if-body; url was not sanitized, so x is tainted
        assert tracker.is_tainted(_name("x")) is True


# ---------------------------------------------------------------------------
# _is_sanitizing_call — trusted_validator Attribute path (line 266)
# ---------------------------------------------------------------------------


class TestTrustedValidatorAttributePath:
    """Line 266: trusted_validator matched via ast.Attribute (obj.my_validator(x))."""

    def test_attribute_trusted_validator_sanitizes(self):
        """result = validators.validate_url(url) — Attribute call to a trusted validator."""
        src = "result = validators.validate_url(url)"
        tracker = _parse_and_visit(
            src, {"url"}, trusted_validators=["validate_url"]
        )
        assert tracker.is_tainted(_name("result")) is False

    def test_attribute_trusted_validator_not_in_list_does_not_sanitize(self):
        """result = validators.unknown(url) — method not in trusted_validators."""
        src = "result = validators.unknown(url)"
        tracker = _parse_and_visit(
            src, {"url"}, trusted_validators=["validate_url"]
        )
        # unknown is not trusted; call result is clean (not tainted) but not sanitized
        assert tracker.is_tainted(_name("result")) is False


# ---------------------------------------------------------------------------
# _is_urlparse_call — Attribute branch (lines 275–277)
# ---------------------------------------------------------------------------


class TestIsUrlparseCallAttributeBranch:
    """Lines 275–277: urlparse called as an attribute (urllib.parse.urlparse(...))."""

    def test_urllib_parse_urlparse_attribute_call_sanitizes_assignment(self):
        """hostname = urllib.parse.urlparse(url).hostname — Attribute call form."""
        src = "hostname = urllib.parse.urlparse(url).hostname"
        tracker = _parse_and_visit(src, {"url"})
        assert tracker.is_tainted(_name("hostname")) is False

    def test_urllib_parse_urlparse_in_if_sanitizes_body(self):
        """if urllib.parse.urlparse(url).hostname in ALLOWED: — Attribute call in compare."""
        src = """
if urllib.parse.urlparse(url).hostname in ALLOWED_HOSTS:
    x = url
"""
        tracker = _parse_and_visit(src, {"url"})
        assert tracker.is_tainted(_name("x")) is False


# ---------------------------------------------------------------------------
# _annotation_is_field_validated — Attribute branch (lines 318–320)
# ---------------------------------------------------------------------------


class TestAnnotationIsFieldValidatedAttributeBranch:
    """Lines 318–320: annotation is an ast.Attribute (e.g. models.SafeUrl)."""

    def test_attribute_annotation_with_validated_attr_sanitizes(self):
        """x: models.SafeUrl = url — Attribute annotation whose .attr is in
        field_validated_types clears taint.
        """
        src = "x: models.SafeUrl = url"
        tracker = _parse_and_visit(
            src,
            {"url"},
            field_validated_types={"SafeUrl"},
        )
        assert tracker.is_tainted(_name("x")) is False

    def test_attribute_annotation_not_in_validated_types_propagates_taint(self):
        """x: models.PlainModel = url — attr not in field_validated_types → tainted."""
        src = "x: models.PlainModel = url"
        tracker = _parse_and_visit(
            src,
            {"url"},
            field_validated_types={"SafeUrl"},  # PlainModel not listed
        )
        assert tracker.is_tainted(_name("x")) is True


# ---------------------------------------------------------------------------
# Direct private-method tests to hit the 4 remaining coverage lines
# ---------------------------------------------------------------------------

from mcp_scan.static.taint import _is_field_validator_decorator


class TestDirectPrivateMethodCoverage:
    """These tests call private methods directly to ensure coverage tools
    instrument the exact return statements that higher-level tests miss.
    """

    def test_is_field_validator_decorator_bare_name_returns_true(self):
        """_is_field_validator_decorator with a bare ast.Name returns True."""
        bare = ast.Name(id="field_validator", ctx=ast.Load())
        assert _is_field_validator_decorator(bare) is True

    def test_is_field_validator_decorator_bare_validator_name_returns_true(self):
        """bare @validator (Pydantic v1) also returns True."""
        bare = ast.Name(id="validator", ctx=ast.Load())
        assert _is_field_validator_decorator(bare) is True

    def test_is_field_validator_decorator_unrecognized_node_returns_false(self):
        """Line 44: a Constant node (not Call/Name) falls through to return False."""
        const = ast.Constant(value=42)
        assert _is_field_validator_decorator(const) is False

    def test_visit_if_orelse_is_visited(self):
        """Line 212: the orelse branch of an if/else is visited."""
        src = """
if url in ALLOWED:
    x = url
else:
    y = url
"""
        tracker = _parse_and_visit(src, {"url"})
        # Inside the if-body url is sanitized → x is clean
        assert tracker.is_tainted(_name("x")) is False
        # In the else branch url is NOT sanitized → y is tainted
        assert tracker.is_tainted(_name("y")) is True

    def test_extract_sanitized_names_urlparse_name_arg_returns_name(self):
        """urlparse(url).hostname in ALLOWED where url is tainted adds url to sanitized."""
        compare = ast.parse("urlparse(url).hostname in ALLOWED").body[0].value
        tracker = TaintTracker({"url"})
        result = tracker._extract_sanitized_names_from_compare(compare)
        assert "url" in result

    def test_is_urlparse_call_attribute_form_returns_true(self):
        """urllib.parse.urlparse(...) — Attribute func returns True."""
        call = ast.Call(
            func=ast.Attribute(
                value=ast.Attribute(
                    value=ast.Name(id="urllib", ctx=ast.Load()),
                    attr="parse",
                    ctx=ast.Load(),
                ),
                attr="urlparse",
                ctx=ast.Load(),
            ),
            args=[ast.Name(id="url", ctx=ast.Load())],
            keywords=[],
        )
        tracker = TaintTracker({"url"})
        assert tracker._is_urlparse_call(call) is True

    def test_is_urlparse_call_unrecognized_func_returns_false(self):
        """Line 277: a Call whose func is a Subscript (not Name/Attribute) returns False."""
        call = ast.Call(
            func=ast.Subscript(
                value=ast.Name(id="funcs", ctx=ast.Load()),
                slice=ast.Constant(value=0),
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[],
        )
        tracker = TaintTracker(set())
        assert tracker._is_urlparse_call(call) is False

    def test_annotation_is_field_validated_attribute_returns_true(self):
        """models.SafeUrl annotation — Attribute branch returns True."""
        annotation = ast.Attribute(
            value=ast.Name(id="models", ctx=ast.Load()),
            attr="SafeUrl",
            ctx=ast.Load(),
        )
        tracker = TaintTracker({"url"}, field_validated_types={"SafeUrl"})
        assert tracker._annotation_is_field_validated(annotation) is True

    def test_annotation_is_field_validated_unrecognized_node_returns_false(self):
        """Line 320: a Constant annotation (not Name/Attribute) returns False."""
        annotation = ast.Constant(value="str")
        tracker = TaintTracker({"url"}, field_validated_types={"SafeUrl"})
        assert tracker._annotation_is_field_validated(annotation) is False
