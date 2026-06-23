from __future__ import annotations

import ast
from typing import Dict, Tuple

from cross_file import FunctionSummary
from taint import TaintAnalyzer


class ScopeAwareAnalyzer(ast.NodeVisitor):
    def __init__(
        self,
        tainted_variables: set[str],
        function_defs: dict[str, ast.FunctionDef],
        function_summaries: dict[str, FunctionSummary],
    ) -> None:
        self.function_defs = function_defs
        self.function_summaries = function_summaries
        self.tainted_variables_stack: list[set[str]] = [set(tainted_variables)]
        self._call_stack: list[str] = []
        # import alias maps for resolving module and from-import names
        # maps local name -> module name (for `import X as Y` or `import X`)
        self.import_aliases: dict[str, str] = {}
        # maps local name -> (module, original_name) for `from M import name as local`
        self.from_imports: dict[str, tuple[str, str]] = {}
        # argparse callback handlers assigned via set_defaults(func=...)
        self.argparse_handler_names: set[str] = set()

    @property
    def tainted_variables(self) -> set[str]:
        return self.tainted_variables_stack[-1]

    def push_scope(
        self,
        tainted_parameters: dict[str, bool] | None = None,
    ) -> None:
        local_taints: set[str] = set()

        if tainted_parameters is not None:
            local_taints.update(
                name
                for name, is_tainted in tainted_parameters.items()
                if is_tainted
            )

        self.tainted_variables_stack.append(local_taints)

    def pop_scope(self) -> None:
        self.tainted_variables_stack.pop()

    def expression_is_tainted(self, node: ast.AST) -> bool:
        return TaintAnalyzer.expression_is_tainted(
            node,
            self.tainted_variables,
            self.function_summaries,
        )

    def _resolve_module_for_name(self, name: str) -> str:
        return self.import_aliases.get(name, name)

    def _is_attr_on_module(self, func: ast.AST, module_name: str, attr_names: set[str]) -> bool:
        if not isinstance(func, ast.Attribute):
            return False
        if not isinstance(func.value, ast.Name):
            return False
        resolved = self._resolve_module_for_name(func.value.id)
        return resolved == module_name and func.attr in attr_names

    def _is_from_import_name(self, func: ast.AST, module_name: str | None, attr_names: set[str]) -> bool:
        if not isinstance(func, ast.Name):
            return False
        local = func.id
        if local not in self.from_imports:
            return False
        mod, orig = self.from_imports[local]
        if module_name is not None and mod != module_name:
            return False
        return orig in attr_names

    def _is_from_import_of(self, func: ast.AST, attr_names: set[str]) -> bool:
        """Return True if `func` is a Name imported from any module and the original name matches attr_names."""
        if not isinstance(func, ast.Name):
            return False
        local = func.id
        if local not in self.from_imports:
            return False
        _, orig = self.from_imports[local]
        return orig in attr_names

    def visit_Module(self, node: ast.Module) -> None:
        # Collect import aliases and from-imports first so analyzers can
        # resolve aliased module/attribute names when checking sinks.
        for statement in node.body:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    local = alias.asname if alias.asname is not None else alias.name
                    self.import_aliases[local] = alias.name.split(".")[0]

            elif isinstance(statement, ast.ImportFrom):
                module = statement.module or ""
                base = module.split(".")[0] if module else ""
                for alias in statement.names:
                    local = alias.asname if alias.asname is not None else alias.name
                    self.from_imports[local] = (base, alias.name)

        # Collect argparse callback handlers defined via parser.set_defaults(func=handler)
        for callback in ast.walk(node):
            if not isinstance(callback, ast.Call):
                continue

            if not isinstance(callback.func, ast.Attribute):
                continue

            if callback.func.attr != "set_defaults":
                continue

            for keyword in callback.keywords:
                if keyword.arg != "func":
                    continue

                if isinstance(keyword.value, ast.Name):
                    self.argparse_handler_names.add(keyword.value.id)

        for statement in node.body:
            if not isinstance(statement, ast.FunctionDef):
                self.visit(statement)
        
        # Also visit function definitions to analyze their bodies
        for statement in node.body:
            if isinstance(statement, ast.FunctionDef):
                self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Analyze function bodies, either at call sites or if they're
        # module-level definitions that may be entry points.
        if node.name not in self._call_stack:
            parameter_names = [
                arg.arg
                for arg in (
                    node.args.posonlyargs
                    + node.args.args
                    + node.args.kwonlyargs
                )
            ]
            
            # Push a new scope for the function
            self.push_scope()
            
            # Analyze the function body
            for statement in node.body:
                self.visit(statement)
            
            # Pop the function scope
            self.pop_scope()

    def visit_Assign(self, node: ast.Assign) -> None:
        if TaintAnalyzer.expression_is_tainted(
            node.value,
            self.tainted_variables,
            self.function_summaries,
        ):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_variables.add(target.id)

        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        # Propagate taint through context-manager bindings,
        # e.g. `with open(tainted_path) as fd:` -> `fd` becomes tainted.
        for item in node.items:
            if item.optional_vars is None:
                continue

            context_is_tainted = TaintAnalyzer.expression_is_tainted(
                item.context_expr,
                self.tainted_variables,
                self.function_summaries,
            )

            if not context_is_tainted:
                continue

            if isinstance(item.optional_vars, ast.Name):
                self.tainted_variables.add(item.optional_vars.id)
            elif isinstance(item.optional_vars, ast.Tuple):
                for element in item.optional_vars.elts:
                    if isinstance(element, ast.Name):
                        self.tainted_variables.add(element.id)

        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        # Keep async context-manager behavior aligned with visit_With.
        self.visit_With(node)

    def visit_Call(self, node: ast.Call) -> None:
        resolved_function_names: list[str] = []

        if isinstance(node.func, ast.Name):
            if (
                node.func.id in self.function_defs
                and node.func.id not in self._call_stack
            ):
                resolved_function_names.append(node.func.id)

        # Support class/module attribute-style calls when the attribute matches
        # a known local/global function definition, e.g. Backup.load_restore_state(...).
        elif isinstance(node.func, ast.Attribute):
            if (
                node.func.attr in self.function_defs
                and node.func.attr not in self._call_stack
            ):
                resolved_function_names.append(node.func.attr)

            # argparse callback dispatch pattern: args.func(args)
            # Conservatively analyze all handlers discovered via set_defaults(func=...).
            if (
                node.func.attr == "func"
                and self.argparse_handler_names
                and node.args
                and TaintAnalyzer.expression_is_tainted(
                    node.args[0],
                    self.tainted_variables,
                    self.function_summaries,
                )
            ):
                for handler_name in self.argparse_handler_names:
                    if (
                        handler_name in self.function_defs
                        and handler_name not in self._call_stack
                    ):
                        resolved_function_names.append(handler_name)

        for resolved_function_name in resolved_function_names:
            function_def = self.function_defs[resolved_function_name]
            parameter_names = [
                arg.arg
                for arg in (
                    function_def.args.posonlyargs
                    + function_def.args.args
                    + function_def.args.kwonlyargs
                )
            ]

            argument_taints = TaintAnalyzer._call_argument_taints(
                node,
                parameter_names,
                self.tainted_variables,
                self.function_summaries,
            )

            self._call_stack.append(resolved_function_name)
            self.push_scope(
                dict(zip(parameter_names, argument_taints))
            )

            for statement in function_def.body:
                self.visit(statement)

            self.pop_scope()
            self._call_stack.pop()

        self.generic_visit(node)
