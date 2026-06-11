from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path


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
    def expression_is_tainted(
        node: ast.AST,
        tainted_variables: set[str],
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
        # args.term
        #
        if isinstance(node, ast.Attribute):
            return TaintAnalyzer.expression_is_tainted(
                node.value,
                tainted_variables,
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
                )
                or
                TaintAnalyzer.expression_is_tainted(
                    node.right,
                    tainted_variables,
                )
            )

        return False

    def visit_Assign(self, node: ast.Assign) -> None:

        if TaintAnalyzer.expression_is_tainted(
            node.value,
            self.tainted_variables,
        ):
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

        if not node.args:
            self.generic_visit(node)
            return

        if not self._is_command_sink(node.func):
            self.generic_visit(node)
            return

        first_arg = node.args[0]

        if TaintAnalyzer.expression_is_tainted(
            first_arg,
            self.tainted_variables,
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


        if not node.args:
            self.generic_visit(node)
            return
        
        if not self._is_code_sink(node.func):
            self.generic_visit(node)
            return

        first_arg = node.args[0]

        if TaintAnalyzer.expression_is_tainted(
            first_arg,
            self.tainted_variables,
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

        if not node.args:
            self.generic_visit(node)
            return

        if self._is_sql_sink(node.func):

            first_arg = node.args[0]

            if TaintAnalyzer.expression_is_tainted(
                first_arg,
                self.tainted_variables,
            ):
                self.findings.append(
                    {
                        "type": "sql_injection",
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
        self.tainted_paths: set[str] = set()
    
    def _path_constructor_uses_tainted_data(
        self,
        node: ast.AST,
    ) -> bool:

        if not isinstance(node, ast.Call):
            return False

        if not (
            isinstance(node.func, ast.Name)
            and node.func.id == "Path"
        ):
            return False

        if not node.args:
            return False

        first_arg = node.args[0]

        return TaintAnalyzer.expression_is_tainted(
            first_arg,
            self.tainted_variables,
        )

    def visit_Assign(self, node: ast.Assign) -> None:

        #
        # path = Path(filename)
        #
        if (
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "Path"
            and node.value.args
        ):
            first_arg = node.value.args[0]

            if TaintAnalyzer.expression_is_tainted(
                first_arg,
                self.tainted_variables,
            ):
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

        self.generic_visit(node)

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
            and node.func.value.id == "os"
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

        if not node.args:
            self.generic_visit(node)
            return
        
        if not self._is_pickle_sink(node.func):
            self.generic_visit(node)
            return

        first_arg = node.args[0]

        if TaintAnalyzer.expression_is_tainted(
            first_arg,
            self.tainted_variables,
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

    findings = analyzer.analyze_file(Path("student/analyzer/test/path_traversal_test.py"))

    for finding in findings:
        print(finding)