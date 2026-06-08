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

    TODO:
    - argparse support
    - input()
    - os.environ
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
        # TODO: argparse.ArgumentParser().parse_args()
        self.generic_visit(node)


class TaintAnalyzer(ast.NodeVisitor):
    """
    Tracks tainted values through assignments.

    Currently supports:

        x = sys.argv[1]
        y = x

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
    - subprocess.call
    - subprocess.Popen
    - subprocess.check_output

    TODO:
    - Implement sink detection
    - Verify tainted flow reaches sink
    """

    def __init__(self, tainted_variables: set[str]) -> None:
        self.tainted_variables = tainted_variables
        self.findings: list[dict] = []

    @staticmethod
    def _is_os_system(func: ast.AST) -> bool:
        return (
            isinstance(func, ast.Attribute)
            and func.attr == "system"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
        )

    def visit_Call(self, node: ast.Call) -> None:

        #
        # Is this an os.system(...) call?
        #
        if not self._is_os_system(node.func):
            self.generic_visit(node)
            return

        #
        # Does it have an argument?
        #
        if not node.args:
            self.generic_visit(node)
            return

        first_arg = node.args[0]

        #
        # Is the argument a tainted variable?
        #
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
    - compile

    TODO:
    - Implement sink detection
    - Verify tainted flow reaches sink
    """

    def __init__(self, tainted_variables: set[str]) -> None:
        self.tainted_variables = tainted_variables
        self.findings: list[dict] = []

    def visit_Call(self, node: ast.Call) -> None:
        # TODO: Code injection detection
        self.generic_visit(node)


class SqlInjectionAnalyzer(ast.NodeVisitor):
    """
    Detects tainted data reaching SQL execution sinks.

    Sinks:
    - cursor.execute
    - cursor.executemany

    TODO:
    - Implement sink detection
    - Detect string-built SQL queries
    - Verify tainted flow reaches sink
    """

    def __init__(self, tainted_variables: set[str]) -> None:
        self.tainted_variables = tainted_variables
        self.findings: list[dict] = []

    def visit_Call(self, node: ast.Call) -> None:
        # TODO: SQL injection detection
        self.generic_visit(node)


class PathTraversalAnalyzer(ast.NodeVisitor):
    """
    Detects tainted paths reaching filesystem operations.

    Sinks:
    - open
    - Path.open
    - Path.read_text
    - Path.write_text
    - os.open

    TODO:
    - Implement sink detection
    - Verify tainted flow reaches sink
    """

    def __init__(self, tainted_variables: set[str]) -> None:
        self.tainted_variables = tainted_variables
        self.findings: list[dict] = []

    def visit_Call(self, node: ast.Call) -> None:
        # TODO: Path traversal detection
        self.generic_visit(node)


class UnsafeDeserializationAnalyzer(ast.NodeVisitor):
    """
    Detects tainted data reaching deserialization sinks.

    Sinks:
    - pickle.load
    - pickle.loads
    - dill.load
    - dill.loads
    - yaml.load

    TODO:
    - Implement sink detection
    - Verify tainted flow reaches sink
    """

    def __init__(self, tainted_variables: set[str]) -> None:
        self.tainted_variables = tainted_variables
        self.findings: list[dict] = []

    def visit_Call(self, node: ast.Call) -> None:
        # TODO: Unsafe deserialization detection
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

    findings = analyzer.analyze_file(Path("student/analyzer/test/command_injection_test.py"))

    print(findings)