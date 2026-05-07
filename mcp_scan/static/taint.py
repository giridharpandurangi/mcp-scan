"""TaintTracker: intra-procedural taint propagation for MCP tool parameters."""

from __future__ import annotations

import ast


def _is_mcp_tool(func_def: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the function has a @mcp.tool() or @server.tool() decorator."""
    for decorator in func_def.decorator_list:
        # Match @mcp.tool() or @server.tool() — ast.Call wrapping ast.Attribute
        if isinstance(decorator, ast.Call):
            func = decorator.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "tool"
                and isinstance(func.value, ast.Name)
                and func.value.id in ("mcp", "server")
            ):
                return True
        # Also match bare @mcp.tool or @server.tool (without call parens)
        elif isinstance(decorator, ast.Attribute):
            if (
                decorator.attr == "tool"
                and isinstance(decorator.value, ast.Name)
                and decorator.value.id in ("mcp", "server")
            ):
                return True
    return False


def _is_field_validator_decorator(decorator: ast.expr) -> bool:
    """Return True if the decorator is @field_validator or @validator."""
    # @field_validator("field_name") or @validator("field_name")
    if isinstance(decorator, ast.Call):
        func = decorator.func
        if isinstance(func, ast.Name) and func.id in ("field_validator", "validator"):
            return True
        if isinstance(func, ast.Attribute) and func.attr in ("field_validator", "validator"):
            return True
    # bare @field_validator (unusual but handle it)
    if isinstance(decorator, ast.Name) and decorator.id in ("field_validator", "validator"):
        return True
    return False


def collect_field_validated_types(tree: ast.AST) -> set[str]:
    """Collect names of Pydantic model classes that have @field_validator decorators.

    These are recognized as sanitizing types for annotated assignments.
    Only classes defined in the same file are considered (MVP scope).
    """
    validated_types: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        has_field_validator = False
        for item in ast.walk(node):
            if isinstance(item, ast.FunctionDef):
                for dec in item.decorator_list:
                    if _is_field_validator_decorator(dec):
                        has_field_validator = True
                        break
            if has_field_validator:
                break
        if has_field_validator:
            validated_types.add(node.name)
    return validated_types


class TaintTracker(ast.NodeVisitor):
    """Tracks tainted data flow from MCP tool parameters to dangerous sinks.

    Performs intra-procedural taint analysis. Taint originates from MCP tool
    handler parameters and propagates through assignments, string concatenation,
    and f-strings. Taint is cleared when a value passes through a recognized
    sanitizer (re.match, membership test, urlparse hostname check, trusted
    validator, or Pydantic field_validator).
    """

    def __init__(
        self,
        tainted_params: set[str],
        trusted_validators: list[str] | None = None,
        field_validated_types: set[str] | None = None,
    ) -> None:
        """Initialize the tracker with the set of initially tainted parameter names.

        Args:
            tainted_params: Names of function parameters that are tainted sources.
            trusted_validators: Names of functions that sanitize their input
                (e.g. ["validate_url", "is_safe_path"]).
            field_validated_types: Names of Pydantic model classes defined in the
                same file that have @field_validator decorators. Variables annotated
                with these types are considered sanitized.
        """
        self._tainted: set[str] = set(tainted_params)
        self._sanitized: set[str] = set()  # names explicitly cleared by sanitizers
        self._trusted_validators: set[str] = set(trusted_validators or [])
        self._field_validated_types: set[str] = set(field_validated_types or [])

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_tainted(self, node: ast.expr) -> bool:
        """Return True if the expression node carries a taint label.

        Handles:
        - ast.Name: tainted if the name is in the tainted set
        - ast.BinOp with ast.Add: tainted if either operand is tainted
        - ast.JoinedStr (f-string): tainted if any value part is tainted
        - Everything else: not tainted (conservative — function call results
          are not propagated as tainted unless explicitly assigned)
        """
        if isinstance(node, ast.Name):
            return node.id in self._tainted and node.id not in self._sanitized

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.is_tainted(node.left) or self.is_tainted(node.right)

        if isinstance(node, ast.JoinedStr):
            # f-string: tainted if any FormattedValue inside is tainted
            for value in node.values:
                if isinstance(value, ast.FormattedValue) and self.is_tainted(value.value):
                    return True
            return False

        return False

    # ------------------------------------------------------------------
    # Visitor methods — taint propagation
    # ------------------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        """Propagate taint from RHS to LHS variable names.

        If the RHS is tainted, all LHS Name targets become tainted.
        If the RHS is a sanitizing expression, LHS names are cleared from taint.
        """
        rhs_tainted = self.is_tainted(node.value)
        rhs_sanitized = self._is_sanitizing_call(node.value)

        for target in node.targets:
            self._apply_taint_to_target(target, rhs_tainted, rhs_sanitized)

        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        """Propagate taint through augmented assignment (e.g. x += expr).

        If the RHS is tainted, the target variable becomes tainted.
        Augmented assignment never clears taint (x += safe_val still keeps
        x tainted if it was tainted before).
        """
        if isinstance(node.target, ast.Name):
            if self.is_tainted(node.value):
                self._tainted.add(node.target.id)
                self._sanitized.discard(node.target.id)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Propagate taint through annotated assignment (e.g. x: str = expr).

        If the annotation refers to a Pydantic field-validated type defined in
        the same file, the variable is considered sanitized regardless of the RHS.
        """
        if node.value is None:
            # Bare annotation with no value — nothing to propagate
            self.generic_visit(node)
            return

        # Check if the annotation type is a field-validated Pydantic model
        annotation_is_validated = self._annotation_is_field_validated(node.annotation)

        if annotation_is_validated:
            # The type annotation itself acts as a sanitizer
            if isinstance(node.target, ast.Name):
                self._tainted.discard(node.target.id)
                self._sanitized.add(node.target.id)
        else:
            rhs_tainted = self.is_tainted(node.value)
            rhs_sanitized = self._is_sanitizing_call(node.value)
            self._apply_taint_to_target(node.target, rhs_tainted, rhs_sanitized)

        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        """Detect sanitization patterns in if-conditions and clear taint in body.

        Recognized patterns:
        - ``if x in ALLOWED``: clears taint on ``x`` within the if-body
        - ``if urlparse(x).hostname in ALLOWED``: clears taint on ``x``
        - ``if re.match(..., x)`` / ``if re.fullmatch(..., x)``: clears taint on ``x``
        """
        sanitized_in_body: set[str] = set()

        test = node.test
        if isinstance(test, ast.Compare):
            sanitized_in_body = self._extract_sanitized_names_from_compare(test)

        # Visit the body with temporarily sanitized names
        saved_sanitized = set(self._sanitized)
        self._sanitized.update(sanitized_in_body)
        for stmt in node.body:
            self.visit(stmt)
        self._sanitized = saved_sanitized

        # Visit the orelse without the sanitization
        for stmt in node.orelse:
            self.visit(stmt)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _apply_taint_to_target(
        self,
        target: ast.expr,
        rhs_tainted: bool,
        rhs_sanitized: bool,
    ) -> None:
        """Apply taint or sanitization to a single assignment target."""
        if isinstance(target, ast.Name):
            if rhs_tainted:
                self._tainted.add(target.id)
                self._sanitized.discard(target.id)
            elif rhs_sanitized:
                self._tainted.discard(target.id)
                self._sanitized.add(target.id)
            else:
                # Clean assignment — remove from tainted (overwritten with safe value)
                self._tainted.discard(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            # Unpacking: x, y = expr — propagate taint to all names
            for elt in target.elts:
                self._apply_taint_to_target(elt, rhs_tainted, rhs_sanitized)

    def _is_sanitizing_call(self, node: ast.expr) -> bool:
        """Return True if the expression is a recognized sanitizing call.

        Recognized sanitizers:
        - ``re.match(pattern, value)``
        - ``re.fullmatch(pattern, value)``
        - Any call to a function in ``self._trusted_validators``
        - ``urlparse(x).hostname`` attribute access (the whole expression)
        """
        if not isinstance(node, ast.Call):
            # Check for attribute access: urlparse(x).hostname
            if isinstance(node, ast.Attribute) and node.attr == "hostname":
                if isinstance(node.value, ast.Call):
                    return self._is_urlparse_call(node.value)
            return False

        # re.match(...) or re.fullmatch(...)
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in ("match", "fullmatch"):
            if isinstance(func.value, ast.Name) and func.value.id == "re":
                return True

        # trusted_validators: any call whose function name is in the list
        if isinstance(func, ast.Name) and func.id in self._trusted_validators:
            return True
        if isinstance(func, ast.Attribute) and func.attr in self._trusted_validators:
            return True

        return False

    def _is_urlparse_call(self, node: ast.Call) -> bool:
        """Return True if the call is urlparse(...) or urllib.parse.urlparse(...)."""
        func = node.func
        if isinstance(func, ast.Name) and func.id == "urlparse":
            return True
        if isinstance(func, ast.Attribute) and func.attr == "urlparse":
            return True
        return False

    def _extract_sanitized_names_from_compare(self, node: ast.Compare) -> set[str]:
        """Extract variable names that are sanitized by a comparison expression.

        Handles:
        - ``x in ALLOWED`` → sanitizes ``x``
        - ``urlparse(x).hostname in ALLOWED`` → sanitizes ``x``
        """
        sanitized: set[str] = set()

        if len(node.ops) != 1 or not isinstance(node.ops[0], ast.In):
            return sanitized

        left = node.left

        # Simple membership test: x in ALLOWED
        if isinstance(left, ast.Name) and left.id in self._tainted:
            sanitized.add(left.id)
            return sanitized

        # urlparse(x).hostname in ALLOWED
        if (
            isinstance(left, ast.Attribute)
            and left.attr == "hostname"
            and isinstance(left.value, ast.Call)
            and self._is_urlparse_call(left.value)
        ):
            # Extract the argument to urlparse
            call = left.value
            if call.args and isinstance(call.args[0], ast.Name):
                arg_name = call.args[0].id
                if arg_name in self._tainted:
                    sanitized.add(arg_name)

        return sanitized

    def _annotation_is_field_validated(self, annotation: ast.expr) -> bool:
        """Return True if the annotation refers to a Pydantic field-validated type."""
        if isinstance(annotation, ast.Name):
            return annotation.id in self._field_validated_types
        if isinstance(annotation, ast.Attribute):
            return annotation.attr in self._field_validated_types
        return False
