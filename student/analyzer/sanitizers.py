from __future__ import annotations

import ast
from typing import Callable


# These patterns are the exploits we want to check for:
# - "../" and "..\\" for path traversal (path.read_text)
# - "&&" for command injection (os.system)
# - "print()" for code injection (eval)
# - "class" for unsafe deserialization (pickle.loads)
# - SQL injection is more complex (too many SQL statements are possible exploits) and can therefore not be reliably detected with constant patterns
_TRAVERSAL_TOKENS = {"../", "..\\", "&&", "print()", "class"}


def _is_constant_str(node: ast.AST, values: set[str] | None = None) -> bool:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return False
    if values is None:
        return True
    return node.value in values


def is_sanitizer_call(
    node: ast.Call,
    tainted_variables: set[str],
    function_summaries: dict | None,
    expression_is_tainted: Callable[[ast.AST, set[str], dict | None], bool],
) -> bool:
    """Return True when a call matches known sanitizer patterns.

    This is intentionally conservative and only recognizes explicit patterns.
    """

    # x.replace("../", "") or x.replace("..\\", ""). finds patterns as describes in _TRAVERSAL_TOKENS
    if isinstance(node.func, ast.Attribute) and node.func.attr == "replace":
        if len(node.args) >= 2:
            pattern, replacement = node.args[0], node.args[1]
            base = node.func.value
            if (
                _is_constant_str(pattern, _TRAVERSAL_TOKENS)
                and _is_constant_str(replacement, {""})
                and expression_is_tainted(base, tainted_variables, function_summaries)
            ):
                return True

    return False


def is_inplace_sanitizer_call(node: ast.Call, tainted_variables: set[str]) -> tuple[bool, str | None]:
    """Detect in-place sanitizers, e.g., tainted_var.remove("../").

    Returns (True, variable_name) when the variable should be untainted.
    """

    if not isinstance(node.func, ast.Attribute):
        return False, None

    if node.func.attr not in {"remove", "discard"}:
        return False, None

    if not isinstance(node.func.value, ast.Name):
        return False, None

    variable_name = node.func.value.id
    if variable_name not in tainted_variables:
        return False, None

    if not node.args:
        return False, None

    token = node.args[0]
    if _is_constant_str(token, _TRAVERSAL_TOKENS):
        return True, variable_name

    return False, None
