from __future__ import annotations

import argparse
import ast
import json
import stat
from pathlib import Path


TOY_TARGET_ID = "toy-command-runner"
TOY_TARGET_DIR = "toy_command_runner"
VULN_TYPE = "command_injection"


class ToyPatternVisitor(ast.NodeVisitor):
    """Find one hard-coded pattern: os.system(command) after an f-string assignment."""

    def __init__(self) -> None:
        self.finding: dict | None = None
        self.current_function = ""
        self.fstring_assignments: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        previous_function = self.current_function
        previous_assignments = self.fstring_assignments
        self.current_function = node.name
        self.fstring_assignments = set()
        self.generic_visit(node)
        self.current_function = previous_function
        self.fstring_assignments = previous_assignments

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.JoinedStr):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.fstring_assignments.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self.finding is not None:
            return
        if not self._is_os_system(node.func):
            self.generic_visit(node)
            return
        if not node.args:
            self.generic_visit(node)
            return
        first_arg = node.args[0]
        if isinstance(first_arg, ast.Name) and first_arg.id in self.fstring_assignments:
            self.finding = {
                "line": node.lineno,
                "function": self.current_function or "<module>",
            }
        self.generic_visit(node)

    @staticmethod
    def _is_os_system(func: ast.AST) -> bool:
        return (
            isinstance(func, ast.Attribute)
            and func.attr == "system"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
        )


def find_toy_vulnerability(target_root: Path) -> dict | None:
    vulnerable_file = target_root / "toybackup" / "runner.py"
    if not vulnerable_file.exists():
        return None
    tree = ast.parse(vulnerable_file.read_text(encoding="utf-8"))
    visitor = ToyPatternVisitor()
    visitor.visit(tree)
    if visitor.finding is None:
        return None
    return {
        "path": "toybackup/runner.py",
        "line": visitor.finding["line"],
        "function": visitor.finding["function"],
    }


def write_toy_exploit(out_dir: Path) -> str:
    exploits_dir = out_dir / "exploits"
    exploits_dir.mkdir(parents=True, exist_ok=True)
    exploit_rel = "exploits/toy-command-runner-command-injection.py"
    exploit_path = out_dir / exploit_rel
    exploit_path.write_text(
        """#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    target_root = Path(os.environ["TARGET_ROOT"])
    marker = Path(os.environ["EXPLOIT_MARKER"])
    env = os.environ.copy()
    env["PYTHONPATH"] = str(target_root / '.')
    payload = "daily; touch $EXPLOIT_MARKER"
    subprocess.run(
        [sys.executable, "-m", "toybackup.cli", payload],
        cwd=target_root,
        check=True,
        env=env,
    )
    if marker.exists():
        print(f"Exploit succeeded, marker found at {marker}")
    else:
        print(f"Exploit failed, marker not found at {marker}")
    return 0 if marker.exists() else 1


if __name__ == "__main__":
    raise SystemExit(main())
""",
        encoding="utf-8",
    )
    exploit_path.chmod(
        exploit_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    )
    return exploit_rel


def get_toy_target_root(targets_dir: Path, targets: list[dict]) -> list[Path]:
    toy_roots = []
    for target in targets:
        target_root = targets_dir / str(target.get("path", ""))
        if target_root.exists() and target_root.name == TOY_TARGET_DIR:
            toy_roots.append(target_root)
    return toy_roots

def load_manifest(targets_dir: Path) -> dict:
    manifest_path = targets_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def analyze(targets_dir: Path, out_dir: Path, single_target_folder: str | None = None) -> dict:
    findings = []
    manifest = load_manifest(targets_dir)

    # If single_target_folder is specified, filter the targets to only include the one with the matching folder name.
    # Otherwise, include all targets from the manifest.
    if single_target_folder:
        targets = [target for target in manifest.get("targets", []) if target.get("path") == single_target_folder]
        if not targets:
            raise ValueError(f"No target found with folder name: {single_target_folder}")
        if len(targets) > 1:
            raise ValueError(f"Multiple targets found with folder name: {single_target_folder}")
    else:
        targets = manifest.get("targets", [])

    for target_root in get_toy_target_root(targets_dir, targets):
        location = find_toy_vulnerability(target_root)
        if location is None:
            continue
        exploit_path = write_toy_exploit(out_dir)
        findings.append(
            {
                "id": "toy-command-runner-command-injection-001",
                "target_id": TOY_TARGET_ID,
                "vulnerability_type": VULN_TYPE,
                "location": location,
                "description": "The job name flows into an f-string command executed by os.system. Passing a job name containing shell metacharacters, such as '; touch /tmp/marker' allows for command injection.",
                "exploit": {
                    "path": exploit_path,
                    "kind": "python",
                }
            }
        )
    return {
        "schema_version": "1.0",
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Naive AST starter analyzer.")
    parser.add_argument("targets", type=Path, help="Target directory or full target bundle")
    parser.add_argument("out", type=Path, help="Writable output directory")
    parser.add_argument("single_target_folder", nargs="?", default=None, help="Optional single target folder to analyze")
    args = parser.parse_args()

    if not args.targets.exists():
        parser.error(f"target directory does not exist: {args.targets}")

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "exploits").mkdir(exist_ok=True)
    report = analyze(args.targets, args.out, args.single_target_folder)
    (args.out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
