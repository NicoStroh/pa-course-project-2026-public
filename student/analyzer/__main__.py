from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path


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

                if (
                    new_summary.return_tainted_independent
                    != summary.return_tainted_independent
                    or new_summary.return_tainted_from_parameters
                    != summary.return_tainted_from_parameters
                ):
                    self.global_summaries[name] = new_summary
                    changed = True

    def _function_returns_tainted(
        self,
        node: ast.FunctionDef,
        tainted_parameters: set[str],
    ) -> bool:
        analyzer = FunctionSummaryAnalyzer(
            set(tainted_parameters),
            self.global_summaries,
        )

        for statement in node.body:
            analyzer.visit(statement)

        return analyzer.return_tainted


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

        for statement in node.body:
            if not isinstance(statement, ast.FunctionDef):
                self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # User-defined functions are analyzed at call sites.
        return None

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

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in self.function_defs
            and node.func.id not in self._call_stack
        ):
            function_name = node.func.id
            function_def = self.function_defs[function_name]
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

            self._call_stack.append(function_name)
            self.push_scope(
                dict(zip(parameter_names, argument_taints))
            )

            for statement in function_def.body:
                self.visit(statement)

            self.pop_scope()
            self._call_stack.pop()

        self.generic_visit(node)


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

        return False

    def visit_Module(self, node: ast.Module) -> None:
        # Collect local function definitions
        for statement in node.body:
            if isinstance(statement, ast.FunctionDef):
                self.function_defs[statement.name] = statement

        # Compute local function summaries (may override pre-existing ones)
        self._compute_function_summaries()

        # Analyze module-level code
        for statement in node.body:
            if not isinstance(statement, ast.FunctionDef):
                self.visit(statement)

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
        analyzer = FunctionSummaryAnalyzer(
            set(tainted_parameters),
            self.function_summaries,
        )

        for statement in node.body:
            analyzer.visit(statement)

        return analyzer.return_tainted

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

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)


class CommandInjectionAnalyzer(ScopeAwareAnalyzer):
    """
    Detects tainted data reaching command execution sinks.

    Sinks:
    - os.system
    - os.popen
    - subprocess.run
    - subprocess.Popen
    """

    def __init__(
        self,
        tainted_variables: set[str],
        function_defs: dict[str, ast.FunctionDef],
        function_summaries: dict[str, FunctionSummary],
    ) -> None:
        super().__init__(
            tainted_variables,
            function_defs,
            function_summaries,
        )
        self.findings: list[dict] = []

    def _is_command_sink(self, func: ast.AST) -> bool:
        # os.system / os.popen
        if self._is_attr_on_module(func, "os", {"system", "popen"}):
            return True

        # subprocess.run / subprocess.Popen
        if self._is_attr_on_module(func, "subprocess", {"run", "Popen"}):
            return True

        # direct from-imports: `from os import system` or `from subprocess import run`
        if self._is_from_import_name(func, "os", {"system", "popen"}):
            return True

        if self._is_from_import_name(func, "subprocess", {"run", "Popen"}):
            return True

        return False

    def visit_Call(self, node: ast.Call) -> None:

        if not node.args:
            super().visit_Call(node)
            return

        if self._is_command_sink(node.func):
            first_arg = node.args[0]

            if self.expression_is_tainted(first_arg):
                self.findings.append(
                    {
                        "type": "command_injection",
                        "line": node.lineno,
                    }
                )

        super().visit_Call(node)


class CodeInjectionAnalyzer(ScopeAwareAnalyzer):
    """
    Detects tainted data reaching code execution sinks.

    Sinks:
    - eval
    - exec
    """

    def __init__(
        self,
        tainted_variables: set[str],
        function_defs: dict[str, ast.FunctionDef],
        function_summaries: dict[str, FunctionSummary],
    ) -> None:
        super().__init__(
            tainted_variables,
            function_defs,
            function_summaries,
        )
        self.findings: list[dict] = []

    def _is_code_sink(self, func: ast.AST) -> bool:
        # direct builtin usage
        if isinstance(func, ast.Name) and func.id in {"eval", "exec"}:
            return True

        # from-imports like `from builtins import eval as e`
        if self._is_from_import_name(func, "builtins", {"eval", "exec"}):
            return True

        return False

    def visit_Call(self, node: ast.Call) -> None:
        if not node.args:
            super().visit_Call(node)
            return

        if self._is_code_sink(node.func):
            first_arg = node.args[0]

            if self.expression_is_tainted(first_arg):
                self.findings.append(
                    {
                        "type": "code_injection",
                        "line": node.lineno,
                    }
                )

        super().visit_Call(node)


class SqlInjectionAnalyzer(ScopeAwareAnalyzer):
    """
    Detects SQL execution sinks.

    Sinks:
    - execute
    - executemany
    - executescript

    TODO:
    - Verify tainted flow reaches sink
    - Detect string-built SQL queries
    """

    def __init__(
        self,
        tainted_variables: set[str],
        function_defs: dict[str, ast.FunctionDef],
        function_summaries: dict[str, FunctionSummary],
    ) -> None:
        super().__init__(
            tainted_variables,
            function_defs,
            function_summaries,
        )
        self.findings: list[dict] = []

    def _is_sql_sink(self, func: ast.AST) -> bool:
        # Attribute-style sinks (e.g., cursor.execute)
        if isinstance(func, ast.Attribute) and func.attr in {
            "execute",
            "executemany",
            "executescript",
        }:
            return True

        # Direct from-imports where the imported name matches one of the SQL calls
        if self._is_from_import_of(func, {"execute", "executemany", "executescript"}):
            return True

        return False

    def visit_Call(self, node: ast.Call) -> None:

        if not node.args:
            super().visit_Call(node)
            return

        if self._is_sql_sink(node.func):
            first_arg = node.args[0]

            if self.expression_is_tainted(first_arg):
                self.findings.append(
                    {
                        "type": "sql_injection",
                        "line": node.lineno,
                    }
                )

        super().visit_Call(node)


class PathTraversalAnalyzer(ScopeAwareAnalyzer):
    """
    Detects tainted paths reaching filesystem operations.

    Sinks:
    - open
    - os.open
    - Path.open
    - Path.read_text
    """

    def __init__(
        self,
        tainted_variables: set[str],
        function_defs: dict[str, ast.FunctionDef],
        function_summaries: dict[str, FunctionSummary],
    ) -> None:
        super().__init__(
            tainted_variables,
            function_defs,
            function_summaries,
        )
        self.findings: list[dict] = []
        self.tainted_paths: set[str] = set()
    
    def _path_constructor_uses_tainted_data(
        self,
        node: ast.AST,
    ) -> bool:

        if not isinstance(node, ast.Call):
            return False

        # Accept direct `Path(...)`, `from pathlib import Path` aliases,
        # and attribute-style `pathlib.Path(...)` (including aliases).
        is_path_constructor = False

        if isinstance(node.func, ast.Name):
            if node.func.id == "Path" or self._is_from_import_name(node.func, "pathlib", {"Path"}):
                is_path_constructor = True

        elif isinstance(node.func, ast.Attribute):
            # e.g. pathlib.Path or pl.Path where `pl` is alias for `pathlib`
            if isinstance(node.func.value, ast.Name) and self._resolve_module_for_name(node.func.value.id) == "pathlib" and node.func.attr == "Path":
                is_path_constructor = True

        if not is_path_constructor:
            return False

        if not node.args:
            return False

        first_arg = node.args[0]

        return self.expression_is_tainted(first_arg)

    def visit_Assign(self, node: ast.Assign) -> None:

        #
        # path = Path(filename)
        #
        if (
            isinstance(node.value, ast.Call)
            and (
                (isinstance(node.value.func, ast.Name) and (node.value.func.id == "Path" or self._is_from_import_name(node.value.func, "pathlib", {"Path"})))
                or (
                    isinstance(node.value.func, ast.Attribute)
                    and isinstance(node.value.func.value, ast.Name)
                    and self._resolve_module_for_name(node.value.func.value.id) == "pathlib"
                    and node.value.func.attr == "Path"
                )
            )
            and node.value.args
        ):
            first_arg = node.value.args[0]

            if self.expression_is_tainted(first_arg):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_paths.add(target.id)

        #
        # other = path
        #
        if isinstance(node.value, ast.Name):

            if node.value.id in self.tainted_paths:

                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_paths.add(target.id)

        super().visit_Assign(node)

    def visit_Call(self, node: ast.Call) -> None:

        #
        # open(filename)
        # os.open(filename, ...)
        #
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "open"
        ) or (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "open"
            and isinstance(node.func.value, ast.Name)
            and self._resolve_module_for_name(node.func.value.id) == "os"
        ):

            if node.args:
                first_arg = node.args[0]

                if TaintAnalyzer.expression_is_tainted(
                    first_arg,
                    self.tainted_variables,
                ):
                    self.findings.append(
                        {
                            "type": "path_traversal",
                            "line": node.lineno,
                        }
                    )

        #
        # path.open()
        # path.read_text()
        #
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"open", "read_text"}
        ):

            #
            # path = Path(filename)
            # path.read_text()
            #
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id in self.tainted_paths
            ):
                self.findings.append(
                    {
                        "type": "path_traversal",
                        "line": node.lineno,
                    }
                )

            #
            # Path(filename).read_text()
            # Path(filename).open()
            #
            elif self._path_constructor_uses_tainted_data(
                node.func.value
            ):
                self.findings.append(
                    {
                        "type": "path_traversal",
                        "line": node.lineno,
                    }
                )

        super().visit_Call(node)


class UnsafeDeserializationAnalyzer(ScopeAwareAnalyzer):
    """
    Detects tainted data reaching deserialization sinks.

    Sinks:
    - pickle.load
    - pickle.loads
    """

    def __init__(
        self,
        tainted_variables: set[str],
        function_defs: dict[str, ast.FunctionDef],
        function_summaries: dict[str, FunctionSummary],
    ) -> None:
        super().__init__(
            tainted_variables,
            function_defs,
            function_summaries,
        )
        self.findings: list[dict] = []

    def _is_pickle_sink(self, func: ast.AST) -> bool:
        # pickle.load / pickle.loads via module attribute
        if self._is_attr_on_module(func, "pickle", {"load", "loads"}):
            return True

        # direct from-imports: `from pickle import load`
        if self._is_from_import_name(func, "pickle", {"load", "loads"}):
            return True

        return False

    def visit_Call(self, node: ast.Call) -> None:

        if not node.args:
            super().visit_Call(node)
            return

        if not self._is_pickle_sink(node.func):
            super().visit_Call(node)
            return

        first_arg = node.args[0]

        if self.expression_is_tainted(first_arg):
            self.findings.append(
                {
                    "type": "unsafe_deserialization",
                    "line": node.lineno,
                }
            )

        super().visit_Call(node)


class TargetAnalyzer:
    """
    Main analysis pipeline.

    Flow:

        Load all Python files
            ↓
        Compute global function summaries
            ↓
        For each file:
            Parse AST
                ↓
            Perform Taint Analysis (with global summaries)
                ↓
            Run Vulnerability Analyses
                ↓
            Generate Findings
    """

    def __init__(self, target_root: Path) -> None:
        self.target_root = target_root
        self.cross_file_analyzer = CrossFileAnalyzer(target_root)
        self.cross_file_analyzer.load_all_modules()
        self.cross_file_analyzer.compute_global_summaries()

    def analyze_file(self, file_path: Path) -> list[dict]:
        tree = ast.parse(file_path.read_text(encoding="utf-8"))

        # Collect local function definitions from this file
        local_function_defs: dict[str, ast.FunctionDef] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                local_function_defs[node.name] = node

        # Merge global and local function definitions
        merged_function_defs = {
            **self.cross_file_analyzer.all_function_defs,
            **local_function_defs,
        }

        # Merge global and local summaries
        merged_summaries = {
            **self.cross_file_analyzer.global_summaries,
        }

        # Compute local-file summaries (may override global ones)
        taint_analyzer = TaintAnalyzer(
            merged_function_defs,
            merged_summaries,
        )
        taint_analyzer.visit(tree)

        findings: list[dict] = []

        command_analyzer = CommandInjectionAnalyzer(
            taint_analyzer.tainted_variables,
            merged_function_defs,
            taint_analyzer.function_summaries,
        )
        command_analyzer.visit(tree)
        findings.extend(command_analyzer.findings)

        code_analyzer = CodeInjectionAnalyzer(
            taint_analyzer.tainted_variables,
            merged_function_defs,
            taint_analyzer.function_summaries,
        )
        code_analyzer.visit(tree)
        findings.extend(code_analyzer.findings)

        sql_analyzer = SqlInjectionAnalyzer(
            taint_analyzer.tainted_variables,
            merged_function_defs,
            taint_analyzer.function_summaries,
        )
        sql_analyzer.visit(tree)
        findings.extend(sql_analyzer.findings)

        path_analyzer = PathTraversalAnalyzer(
            taint_analyzer.tainted_variables,
            merged_function_defs,
            taint_analyzer.function_summaries,
        )
        path_analyzer.visit(tree)
        findings.extend(path_analyzer.findings)

        deserialization_analyzer = UnsafeDeserializationAnalyzer(
            taint_analyzer.tainted_variables,
            merged_function_defs,
            taint_analyzer.function_summaries,
        )
        deserialization_analyzer.visit(tree)
        findings.extend(deserialization_analyzer.findings)

        for finding in findings:
            finding["path"] = str(
                file_path.relative_to(
                    self.target_root
                )
            )

        return findings

    def analyze(self) -> list[dict]:
        findings: list[dict] = []

        for py_file in self.target_root.rglob("*.py"):
            findings.extend(self.analyze_file(py_file))

        return findings

def load_manifest(targets_dir: Path) -> dict:

    manifest_path = targets_dir / "manifest.json"

    if not manifest_path.exists():
        raise FileNotFoundError(
            f"Manifest not found: {manifest_path}"
        )

    return json.loads(
        manifest_path.read_text(
            encoding="utf-8"
        )
    )

def analyze(
    targets_dir: Path,
    out_dir: Path,
) -> dict:

    findings: list[dict] = []

    manifest = load_manifest(targets_dir)

    for target in manifest.get("targets", []):

        target_root = (
            targets_dir
            / str(target.get("path", ""))
        )

        if not target_root.exists():
            continue

        analyzer = TargetAnalyzer(
            target_root
        )

        target_findings = analyzer.analyze()

        for index, finding in enumerate(
            target_findings,
            start=1,
        ):
            findings.append(
                {
                    "id":
                        f"{target.get('id', 'unknown')}"
                        f"-{finding['type']}"
                        f"-{index}",

                    "target_id":
                        target.get(
                            "id",
                            "unknown",
                        ),

                    "vulnerability_type":
                        finding["type"],

                    "location":
                        {
                            "line":
                                finding["line"]
                        },

                    "description":
                        (
                            f"Detected "
                            f"{finding['type']}"
                        ),
                }
            )

    return {
        "schema_version": "1.0",
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", type=Path)
    parser.add_argument("out", type=Path)

    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    report = analyze(args.targets, args.out)

    (args.out / "report.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    return 0


if __name__ == "__main__":
    analyzer = TargetAnalyzer(Path("."))

    findings = analyzer.analyze_file(Path("student/analyzer/test/command_injection_test.py"))

    for finding in findings:
        print(finding)