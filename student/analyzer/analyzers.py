from __future__ import annotations

import ast

from scope import ScopeAwareAnalyzer
from taint import TaintAnalyzer


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
        function_summaries: dict[str, object],
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
                        "path": getattr(node, "source_path", None),
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
        function_summaries: dict[str, object],
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
                        "path": getattr(node, "source_path", None),
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
    """

    def __init__(
        self,
        tainted_variables: set[str],
        function_defs: dict[str, ast.FunctionDef],
        function_summaries: dict[str, object],
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
                        "path": getattr(node, "source_path", None),
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
        function_summaries: dict[str, object],
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
                            "path": getattr(node, "source_path", None),
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
                        "path": getattr(node, "source_path", None),
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
                        "path": getattr(node, "source_path", None),
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
        function_summaries: dict[str, object],
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
                    "path": getattr(node, "source_path", None),
                }
            )

        super().visit_Call(node)
