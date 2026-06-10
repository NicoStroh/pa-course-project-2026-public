from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path


class SourceCollector(ast.NodeVisitor):
    """
    Finds attacker-controlled inputs.

    Current scope:
    - sys.argv
    """

    def __init__(self) -> None:
        self.sources: list[ast.AST] = []

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """
        Detect:

            sys.argv[1]
            sys.argv[2]
            ...
        """

        if (
            isinstance(node.value, ast.Attribute)
            and node.value.attr == "argv"
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "sys"
        ):
            self.sources.append(node)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """
        Detect:

            parser.parse_args()
        """

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "parse_args"
        ):
            self.sources.append(node)

        self.generic_visit(node)


class TaintAnalyzer(ast.NodeVisitor):
    """
    Tracks tainted values through assignments.

    Currently supports:

        x = sys.argv[1]
        y = x
        y = f"ls {x}"
        y = "ls " + x

    TODO:
    - Function argument propagation
    - Return value propagation
    - Interprocedural analysis
    """

    def __init__(self) -> None:
        self.tainted_variables: set[str] = set()

    @staticmethod
    def _is_sys_argv(node: ast.AST) -> bool:
        """
        Detect:

            sys.argv[1]
        """

        return (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "argv"
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "sys"
        )
    
    @staticmethod
    def _is_parse_args(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "parse_args"
        )

    def _joined_str_is_tainted(self, node: ast.JoinedStr) -> bool:
        for value in node.values:

            if not isinstance(value, ast.FormattedValue):
                continue

            if (
                isinstance(value.value, ast.Name)
                and value.value.id in self.tainted_variables
            ):
                return True

        return False

    def _binop_is_tainted(self, node: ast.BinOp) -> bool:

        if (
            isinstance(node.left, ast.Name)
            and node.left.id in self.tainted_variables
        ):
            return True

        if (
            isinstance(node.right, ast.Name)
            and node.right.id in self.tainted_variables
        ):
            return True

        return False

    def visit_Assign(self, node: ast.Assign) -> None:

        rhs_is_tainted = False

        #
        # Case 1:
        #
        #   x = sys.argv[1]
        #
        if self._is_sys_argv(node.value):
            rhs_is_tainted = True

        #
        # Case 2:
        #
        #   y = x
        #
        elif (
            isinstance(node.value, ast.Name)
            and node.value.id in self.tainted_variables
        ):
            rhs_is_tainted = True

        # Case 3:
        # cmd = f"ls {user}"
        elif (
            isinstance(node.value, ast.JoinedStr)
            and self._joined_str_is_tainted(node.value)
        ):
            rhs_is_tainted = True

        # Case 4:
        # cmd = "ls" + user
        elif (
            isinstance(node.value, ast.BinOp)
            and self._binop_is_tainted(node.value)
        ):
            rhs_is_tainted = True

        #
        # args = parser.parse_args()
        #
        elif self._is_parse_args(node.value):
            rhs_is_tainted = True

        elif (
            isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id in self.tainted_variables
        ):
            rhs_is_tainted = True

        if rhs_is_tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_variables.add(target.id)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # TODO: Function taint propagation
        self.generic_visit(node)


class CommandInjectionAnalyzer(ast.NodeVisitor):
    """
    Detects tainted data reaching command execution sinks.

    Sinks:
    - os.system
    - os.popen
    - subprocess.run
    - subprocess.Popen
    """

    def __init__(self, tainted_variables: set[str]) -> None:
        self.tainted_variables = tainted_variables
        self.findings: list[dict] = []

    @staticmethod
    def _is_command_sink(func: ast.AST) -> bool:

        if not isinstance(func, ast.Attribute):
            return False

        #
        # os.system
        # os.popen
        #
        if (
            isinstance(func.value, ast.Name)
            and func.value.id == "os"
            and func.attr in {"system", "popen"}
        ):
            return True

        #
        # subprocess.run
        # subprocess.Popen
        #
        if (
            isinstance(func.value, ast.Name)
            and func.value.id == "subprocess"
            and func.attr in {"run", "Popen"}
        ):
            return True

        return False

    def visit_Call(self, node: ast.Call) -> None:

        if not self._is_command_sink(node.func):
            self.generic_visit(node)
            return

        if not node.args:
            self.generic_visit(node)
            return

        first_arg = node.args[0]

        if (
            isinstance(first_arg, ast.Name)
            and first_arg.id in self.tainted_variables
        ):
            self.findings.append(
                {
                    "type": "command_injection",
                    "line": node.lineno,
                }
            )

        self.generic_visit(node)


class CodeInjectionAnalyzer(ast.NodeVisitor):
    """
    Detects tainted data reaching code execution sinks.

    Sinks:
    - eval
    - exec
    """

    def __init__(self, tainted_variables: set[str]) -> None:
        self.tainted_variables = tainted_variables
        self.findings: list[dict] = []

    @staticmethod
    def _is_code_sink(func: ast.AST) -> bool:
        return (
            isinstance(func, ast.Name)
            and func.id in {"eval", "exec"}
        )

    def visit_Call(self, node: ast.Call) -> None:

        if not self._is_code_sink(node.func):
            self.generic_visit(node)
            return

        if not node.args:
            self.generic_visit(node)
            return

        first_arg = node.args[0]

        if (
            isinstance(first_arg, ast.Name)
            and first_arg.id in self.tainted_variables
        ):
            self.findings.append(
                {
                    "type": "code_injection",
                    "line": node.lineno,
                }
            )

        self.generic_visit(node)


class SqlInjectionAnalyzer(ast.NodeVisitor):
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

    def __init__(self, tainted_variables: set[str]) -> None:
        self.tainted_variables = tainted_variables
        self.findings: list[dict] = []

    @staticmethod
    def _is_sql_sink(func: ast.AST) -> bool:
        return (
            isinstance(func, ast.Attribute)
            and func.attr in {
                "execute",
                "executemany",
                "executescript",
            }
        )

    def visit_Call(self, node: ast.Call) -> None:

        if self._is_sql_sink(node.func):

            first_arg = node.args[0]

            if (
                isinstance(first_arg, ast.Name)
                and first_arg.id in self.tainted_variables
            ):
                self.findings.append(
                    {
                        "type": "sql_sink",
                        "line": node.lineno,
                    }
                )

        self.generic_visit(node)


class PathTraversalAnalyzer(ast.NodeVisitor):
    """
    Detects tainted paths reaching filesystem operations.

    Sinks:
    - open
    - os.open
    - Path.open
    - Path.read_text
    """

    def __init__(self, tainted_variables: set[str]) -> None:
        self.tainted_variables = tainted_variables
        self.findings: list[dict] = []

    @staticmethod
    def _is_path_sink(func: ast.AST) -> bool:

        if (
            isinstance(func, ast.Name)
            and func.id == "open"
        ):
            return True

        if (
            isinstance(func, ast.Attribute)
            and func.attr == "open"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
        ):
            return True

        if (
            isinstance(func, ast.Attribute)
            and func.attr in {
                "open",
                "read_text",
            }
        ):
            return True

        return False

    def visit_Call(self, node: ast.Call) -> None:

        if not self._is_path_sink(node.func):
            self.generic_visit(node)
            return

        if not node.args:
            self.generic_visit(node)
            return

        first_arg = node.args[0]

        if (
            isinstance(first_arg, ast.Name)
            and first_arg.id in self.tainted_variables
        ):
            self.findings.append(
                {
                    "type": "path_traversal",
                    "line": node.lineno,
                }
            )

        self.generic_visit(node)


class UnsafeDeserializationAnalyzer(ast.NodeVisitor):
    """
    Detects tainted data reaching deserialization sinks.

    Sinks:
    - pickle.load
    - pickle.loads
    """

    def __init__(self, tainted_variables: set[str]) -> None:
        self.tainted_variables = tainted_variables
        self.findings: list[dict] = []

    @staticmethod
    def _is_pickle_sink(func: ast.AST) -> bool:
        return (
            isinstance(func, ast.Attribute)
            and func.attr in {"load", "loads"}
            and isinstance(func.value, ast.Name)
            and func.value.id == "pickle"
        )

    def visit_Call(self, node: ast.Call) -> None:

        if not self._is_pickle_sink(node.func):
            self.generic_visit(node)
            return

        if not node.args:
            self.generic_visit(node)
            return

        first_arg = node.args[0]

        if (
            isinstance(first_arg, ast.Name)
            and first_arg.id in self.tainted_variables
        ):
            self.findings.append(
                {
                    "type": "unsafe_deserialization",
                    "line": node.lineno,
                }
            )

        self.generic_visit(node)


class TargetAnalyzer:
    """
    Main analysis pipeline.

    Flow:

        Parse AST
            ↓
        Collect Sources
            ↓
        Perform Taint Analysis
            ↓
        Run Vulnerability Analyses
            ↓
        Generate Findings
    """

    def __init__(self, target_root: Path) -> None:
        self.target_root = target_root

    def analyze_file(self, file_path: Path) -> list[dict]:
        tree = ast.parse(file_path.read_text(encoding="utf-8"))

        source_collector = SourceCollector()
        source_collector.visit(tree)

        taint_analyzer = TaintAnalyzer()
        taint_analyzer.visit(tree)

        findings: list[dict] = []

        command_analyzer = CommandInjectionAnalyzer(
            taint_analyzer.tainted_variables
        )
        command_analyzer.visit(tree)
        findings.extend(command_analyzer.findings)

        code_analyzer = CodeInjectionAnalyzer(
            taint_analyzer.tainted_variables
        )
        code_analyzer.visit(tree)
        findings.extend(code_analyzer.findings)

        sql_analyzer = SqlInjectionAnalyzer(
            taint_analyzer.tainted_variables
        )
        sql_analyzer.visit(tree)
        findings.extend(sql_analyzer.findings)

        path_analyzer = PathTraversalAnalyzer(
            taint_analyzer.tainted_variables
        )
        path_analyzer.visit(tree)
        findings.extend(path_analyzer.findings)

        deserialization_analyzer = UnsafeDeserializationAnalyzer(
            taint_analyzer.tainted_variables
        )
        deserialization_analyzer.visit(tree)
        findings.extend(deserialization_analyzer.findings)

        return findings

    def analyze(self) -> list[dict]:
        findings: list[dict] = []

        for py_file in self.target_root.rglob("*.py"):
            findings.extend(self.analyze_file(py_file))

        return findings


def analyze(targets_dir: Path, out_dir: Path) -> dict:
    """
    TODO:
    - Iterate over manifest targets
    - Analyze every package
    - Generate exploit scripts
    - Attach exploit paths to findings
    """

    findings: list[dict] = []

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

    findings = analyzer.analyze_file(Path("student/analyzer/test/path_traversal_test.py"))

    print(findings)