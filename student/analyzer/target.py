from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path

from cross_file import CrossFileAnalyzer
from taint import TaintAnalyzer
from analyzers import (
    CommandInjectionAnalyzer,
    CodeInjectionAnalyzer,
    SqlInjectionAnalyzer,
    PathTraversalAnalyzer,
    UnsafeDeserializationAnalyzer,
)


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

        relative_path = str(
            file_path.relative_to(
                self.target_root
            )
        )

        # Attach source metadata for all nodes in the file being analyzed.
        for node in ast.walk(tree):
            setattr(node, "source_path", relative_path)

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

        # Normalize and deduplicate findings so identical sink reports are
        # emitted once even if multiple traversal paths reach the same call.
        deduped_findings: list[dict] = []
        seen: set[tuple[str, int, str]] = set()

        for finding in findings:
            finding_path = str(finding.get("path") or relative_path)
            finding["path"] = finding_path

            finding_type = str(finding.get("type", ""))
            line = int(finding.get("line", -1))
            key = (finding_type, line, finding_path)

            if key in seen:
                continue

            seen.add(key)
            deduped_findings.append(finding)

        return deduped_findings

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
