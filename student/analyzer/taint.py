from __future__ import annotations

import ast
from typing import Dict, List, Set

from cross_file import FunctionSummary
from sanitizers import is_inplace_sanitizer_call, is_sanitizer_call


class TaintAnalyzer(ast.NodeVisitor):
    """
    Tracks tainted values through assignments with support for interprocedural propagation.

    Supports:
    - x = sys.argv[1]
    - y = x
    - y = f"ls {x}"
    - y = "ls " + x
    - y = foo(x)
    - Cross-file function summaries
    """

    def __init__(
        self,
        function_defs: dict[str, ast.FunctionDef] | None = None,
        function_summaries: dict[str, FunctionSummary] | None = None,
    ) -> None:
        self.tainted_variables: set[str] = set()
        self.function_defs: dict[str, ast.FunctionDef] = function_defs or {}
        self.function_summaries: dict[str, FunctionSummary] = function_summaries or {}

    @staticmethod
    def _call_argument_taints(
        node: ast.Call,
        parameter_names: list[str],
        tainted_variables: set[str],
        function_summaries: dict[str, FunctionSummary],
    ) -> list[bool]:
        argument_taints = [False] * len(parameter_names)

        for index, argument in enumerate(node.args):
            if index < len(parameter_names):
                argument_taints[index] = TaintAnalyzer.expression_is_tainted(
                    argument,
                    tainted_variables,
                    function_summaries,
                )

        for keyword in node.keywords:
            if keyword.arg is None:
                continue

            if keyword.arg in parameter_names:
                argument_taints[parameter_names.index(keyword.arg)] = (
                    TaintAnalyzer.expression_is_tainted(
                        keyword.value,
                        tainted_variables,
                        function_summaries,
                    )
                )

        return argument_taints

    @staticmethod
    def expression_is_tainted(
        node: ast.AST,
        tainted_variables: set[str],
        function_summaries: dict[str, FunctionSummary] | None = None,
    ) -> bool:

        #
        # variable
        #
        if isinstance(node, ast.Name):
            return node.id in tainted_variables

        #
        # subscript (e.g. args[0], x[1:]) -> tainted if base is tainted.
        # Also handle `sys.argv[...]` specially.
        #
        if isinstance(node, ast.Subscript):
            # sys.argv[...] -> tainted
            if (
                isinstance(node.value, ast.Attribute)
                and node.value.attr == "argv"
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "sys"
            ):
                return True

            return TaintAnalyzer.expression_is_tainted(
                node.value,
                tainted_variables,
                function_summaries,
            )

        #
        # sys.argv[1]
        #
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "argv"
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "sys"
        ):
            return True

        #
        # parser.parse_args()
        #
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "parse_args"
        ):
            return True

        #
        # function call
        #
        if isinstance(node, ast.Call):
            # Known sanitizers override taint on their returned value.
            if is_sanitizer_call(
                node,
                tainted_variables,
                function_summaries,
                TaintAnalyzer.expression_is_tainted,
            ):
                return False

            if (
                function_summaries is not None
                and isinstance(node.func, ast.Name)
                and node.func.id in function_summaries
            ):
                summary = function_summaries[node.func.id]
                return summary.returns_tainted(
                    TaintAnalyzer._call_argument_taints(
                        node,
                        summary.parameter_names,
                        tainted_variables,
                        function_summaries,
                    )
                )

            # If not a summarized/user function, propagate taint from any argument
            for arg in node.args:
                if TaintAnalyzer.expression_is_tainted(
                    arg,
                    tainted_variables,
                    function_summaries,
                ):
                    return True

            for kw in node.keywords:
                if kw.arg is None:
                    if TaintAnalyzer.expression_is_tainted(
                        kw.value,
                        tainted_variables,
                        function_summaries,
                    ):
                        return True
                else:
                    if TaintAnalyzer.expression_is_tainted(
                        kw.value,
                        tainted_variables,
                        function_summaries,
                    ):
                        return True

        #
        # args.term
        #
        if isinstance(node, ast.Attribute):
            return TaintAnalyzer.expression_is_tainted(
                node.value,
                tainted_variables,
                function_summaries,
            )

        #
        # f"...{user}..."
        #
        if isinstance(node, ast.JoinedStr):

            for value in node.values:

                if (
                    isinstance(value, ast.FormattedValue)
                    and TaintAnalyzer.expression_is_tainted(
                        value.value,
                        tainted_variables,
                        function_summaries,
                    )
                ):
                    return True

            return False

        #
        # "abc" + user
        #
        if isinstance(node, ast.BinOp):

            return (
                TaintAnalyzer.expression_is_tainted(
                    node.left,
                    tainted_variables,
                    function_summaries,
                )
                or
                TaintAnalyzer.expression_is_tainted(
                    node.right,
                    tainted_variables,
                    function_summaries,
                )
            )

        #
        # conditional expression: a if cond else b
        #
        if isinstance(node, ast.IfExp):
            return (
                TaintAnalyzer.expression_is_tainted(
                    node.body,
                    tainted_variables,
                    function_summaries,
                )
                or TaintAnalyzer.expression_is_tainted(
                    node.orelse,
                    tainted_variables,
                    function_summaries,
                )
            )

        #
        # comparison: a == b, a < b, etc.
        #
        if isinstance(node, ast.Compare):
            # If left operand is tainted, the comparison is tainted
            if TaintAnalyzer.expression_is_tainted(
                node.left,
                tainted_variables,
                function_summaries,
            ):
                return True

            # If any right operand is tainted, the comparison is tainted
            for comparator in node.comparators:
                if TaintAnalyzer.expression_is_tainted(
                    comparator,
                    tainted_variables,
                    function_summaries,
                ):
                    return True

            return False

        return False

    def visit_Module(self, node: ast.Module) -> None:
        # Collect local function definitions
        for statement in node.body:
            if isinstance(statement, ast.FunctionDef):
                self.function_defs[statement.name] = statement

        # Compute local function summaries (may override pre-existing ones)
        self._compute_function_summaries()

        # Analyze module-level code with implicit-taint propagation.
        # We iterate to a fixed point because implicit taints can cause
        # further explicit taints in later statements.
        from control_flow import propagate_implicit_taints

        module_stmts = [s for s in node.body if not isinstance(s, ast.FunctionDef)]

        # Represent module body as a fake FunctionDef for the CFG builder.
        fake_func = ast.FunctionDef(
            name="<module>",
            args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
            body=module_stmts,
            decorator_list=[],
        )

        changed = True
        while changed:
            changed = False

            # Visit statements to collect explicit taints
            for statement in module_stmts:
                self.visit(statement)

            # Propagate implicit taints from control dependencies
            implicit = propagate_implicit_taints(
                fake_func,
                self.tainted_variables,
                self.function_summaries,
            )

            for v in implicit:
                if v not in self.tainted_variables:
                    self.tainted_variables.add(v)
                    changed = True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Function bodies are analyzed through summaries, not as module-level statements.
        return None

    def _compute_function_summaries(self) -> None:
        self.function_summaries = {
            name: FunctionSummary(
                name,
                [
                    arg.arg
                    for arg in (
                        node.args.posonlyargs
                        + node.args.args
                        + node.args.kwonlyargs
                    )
                ],
            )
            for name, node in self.function_defs.items()
        }

        changed = True

        while changed:
            changed = False

            for name, node in self.function_defs.items():
                summary = self.function_summaries[name]
                new_summary = FunctionSummary(
                    name,
                    summary.parameter_names,
                )

                new_summary.return_tainted_independent = self._function_returns_tainted(
                    node,
                    set(),
                )

                for parameter_name in summary.parameter_names:
                    if self._function_returns_tainted(
                        node,
                        {parameter_name},
                    ):
                        new_summary.return_tainted_from_parameters.add(
                            parameter_name,
                        )

                if (
                    new_summary.return_tainted_independent
                    != summary.return_tainted_independent
                    or new_summary.return_tainted_from_parameters
                    != summary.return_tainted_from_parameters
                ):
                    self.function_summaries[name] = new_summary
                    changed = True

    def _function_returns_tainted(
        self,
        node: ast.FunctionDef,
        tainted_parameters: set[str],
    ) -> bool:
        analyzer = __import__("cross_file", fromlist=["FunctionSummaryAnalyzer"]).FunctionSummaryAnalyzer(
            set(tainted_parameters),
            self.function_summaries,
        )

        for statement in node.body:
            analyzer.visit(statement)

        return analyzer.return_tainted

    def visit_Assign(self, node: ast.Assign) -> None:
        value_is_tainted = TaintAnalyzer.expression_is_tainted(
            node.value,
            self.tainted_variables,
            self.function_summaries,
        )

        for target in node.targets:
            if isinstance(target, ast.Name):
                if value_is_tainted:
                    self.tainted_variables.add(target.id)
                else:
                    # Strong update for simple assignments: if RHS is not tainted
                    # (including known sanitizer calls), target is considered untainted.
                    self.tainted_variables.discard(target.id)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # In-place sanitizers, e.g., tainted_var.remove("../")
        # should untaint the base variable when we know the removed token.
        inplace_sanitized, variable_name = is_inplace_sanitizer_call(
            node,
            self.tainted_variables,
        )
        if inplace_sanitized and variable_name is not None:
            self.tainted_variables.discard(variable_name)

        self.generic_visit(node)
