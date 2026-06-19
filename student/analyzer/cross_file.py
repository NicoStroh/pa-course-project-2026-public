from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List, Set


class FunctionSummary:
    def __init__(
        self,
        name: str,
        parameter_names: list[str],
    ) -> None:
        self.name = name
        self.parameter_names = parameter_names
        self.return_tainted_independent: bool = False
        self.return_tainted_from_parameters: set[str] = set()
        # Interprocedural control-flow: True if this function has calls in control-dependent blocks
        self.has_calls_in_control_dependent_blocks: bool = False

    def returns_tainted(
        self,
        argument_taints: list[bool],
    ) -> bool:
        if self.return_tainted_independent:
            return True

        for parameter_name, argument_taint in zip(
            self.parameter_names,
            argument_taints,
        ):
            if argument_taint and parameter_name in self.return_tainted_from_parameters:
                return True

        return False


class FunctionSummaryAnalyzer(ast.NodeVisitor):
    def __init__(
        self,
        tainted_variables: set[str],
        function_summaries: dict[str, FunctionSummary],
    ) -> None:
        self.tainted_variables = set(tainted_variables)
        self.function_summaries = function_summaries
        self.return_tainted: bool = False

    def visit_Assign(self, node: ast.Assign) -> None:
        from taint import TaintAnalyzer

        if TaintAnalyzer.expression_is_tainted(
            node.value,
            self.tainted_variables,
            self.function_summaries,
        ):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_variables.add(target.id)

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        from taint import TaintAnalyzer

        if node.value is not None and TaintAnalyzer.expression_is_tainted(
            node.value,
            self.tainted_variables,
            self.function_summaries,
        ):
            self.return_tainted = True

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Do not analyze nested functions when summarizing the outer function.
        return None


class CrossFileAnalyzer:
    """Builds global function summaries across all Python files in a target directory."""

    def __init__(self, target_root: Path) -> None:
        self.target_root = target_root
        self.module_asts: dict[str, ast.Module] = {}
        self.all_function_defs: dict[str, ast.FunctionDef] = {}
        self.global_summaries: dict[str, FunctionSummary] = {}

    def load_all_modules(self) -> None:
        """Parse all .py files in the target directory."""
        for py_file in self.target_root.rglob("*.py"):
            try:
                module_name = py_file.stem
                text = py_file.read_text(encoding="utf-8")
                tree = ast.parse(text)
                self.module_asts[module_name] = tree

                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        self.all_function_defs[node.name] = node
            except Exception:
                pass

    def compute_global_summaries(self) -> None:
        """Compute function summaries across all modules using fixed-point iteration."""
        self.global_summaries = {
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
            for name, node in self.all_function_defs.items()
        }

        changed = True

        while changed:
            changed = False

            for name, node in self.all_function_defs.items():
                summary = self.global_summaries[name]
                new_summary = FunctionSummary(
                    name,
                    summary.parameter_names,
                )

                new_summary.return_tainted_independent = (
                    self._function_returns_tainted(
                        node,
                        set(),
                    )
                )

                for parameter_name in summary.parameter_names:
                    if self._function_returns_tainted(
                        node,
                        {parameter_name},
                    ):
                        new_summary.return_tainted_from_parameters.add(
                            parameter_name,
                        )

                # Check for interprocedural control-flow: calls in control-dependent blocks
                new_summary.has_calls_in_control_dependent_blocks = (
                    self._function_has_calls_in_control_dependent_blocks(node)
                )

                if (
                    new_summary.return_tainted_independent
                    != summary.return_tainted_independent
                    or new_summary.return_tainted_from_parameters
                    != summary.return_tainted_from_parameters
                    or new_summary.has_calls_in_control_dependent_blocks
                    != summary.has_calls_in_control_dependent_blocks
                ):
                    self.global_summaries[name] = new_summary
                    changed = True

    def _function_has_calls_in_control_dependent_blocks(
        self,
        node: ast.FunctionDef,
    ) -> bool:
        """Check if function has calls in control-dependent blocks (interprocedural control-flow)."""
        from cfg import build_cfg_for_function

        cfg = build_cfg_for_function(node)

        # Any call in a control-dependent block means this function has such calls
        for cond_bid, dependent_bids in getattr(cfg, "control_deps", {}).items():
            for bid in dependent_bids:
                block = cfg.blocks.get(bid)
                if block:
                    for stmt in block.stmts:
                        if isinstance(stmt, ast.Call):
                            return True
                        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                            return True
                        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
                            return True

        return False

    def _function_returns_tainted(
        self,
        node: ast.FunctionDef,
        tainted_parameters: set[str],
    ) -> bool:
        # Import here to avoid circular dependency
        from control_flow import propagate_implicit_taints

        # We perform a fixed-point iteration: analyze explicit taints,
        # then compute implicit taints from control dependencies, and
        # repeat until stable. This conservatively captures returns
        # that become tainted due to control-flow.
        current_tainted = set(tainted_parameters)

        while True:
            analyzer = FunctionSummaryAnalyzer(
                set(current_tainted),
                self.global_summaries,
            )

            for statement in node.body:
                analyzer.visit(statement)

            implicit = propagate_implicit_taints(
                node,
                analyzer.tainted_variables,
                self.global_summaries,
            )

            new_tainted = set(current_tainted) | analyzer.tainted_variables | set(implicit)

            if new_tainted == current_tainted:
                return analyzer.return_tainted

            current_tainted = new_tainted
