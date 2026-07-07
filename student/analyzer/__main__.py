from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add the analyzer directory to sys.path so relative imports work
# when the module is invoked via `python -m analyzer`.
sys.path.insert(0, str(Path(__file__).parent.absolute()))

from target import TargetAnalyzer
from exploit_generation import generate_exploit


REPO_ROOT = Path(__file__).resolve().parents[2]
STUDENT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGETS_DIR = STUDENT_ROOT / "targets"

# One-click run configuration (used when this file is run with no CLI args).
# Change this path to the file you want to analyze from the Run button.
RUN_FILE_PATH = Path("student/analyzer/test/if_test.py")

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
    single_target_folder: str | None = None,
) -> dict:

    findings: list[dict] = []

    manifest = load_manifest(targets_dir)

    targets = manifest.get("targets", [])

    if single_target_folder:
        requested = single_target_folder.strip()

        def normalize(name: str) -> str:
            return name.strip().lower().replace("_", "-")

        requested_normalized = normalize(requested)

        filtered_targets = [
            target
            for target in targets
            if requested in {
                str(target.get("id", "")),
                str(target.get("path", "")),
            }
            or requested_normalized in {
                normalize(str(target.get("id", ""))),
                normalize(str(target.get("path", ""))),
            }
        ]

        if not filtered_targets:
            raise ValueError(f"No target found with folder name or id: {single_target_folder}")

        if len(filtered_targets) > 1:
            raise ValueError(
                f"Multiple targets found for: {single_target_folder}"
            )

        targets = filtered_targets

    for target in targets:

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
            entry = {
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
                        "path":
                            finding.get("path", ""),
                        "line":
                            finding["line"]
                    },

                "description":
                    (
                        f"Detected "
                        f"{finding['type']}"
                    ),
            }

            exploit_ref = generate_exploit(
                finding,
                target_root,
                out_dir,
                target,
            )
            if exploit_ref is not None:
                entry["exploit"] = exploit_ref

            findings.append(entry)

    return {
        "schema_version": "1.0",
        "findings": findings,
    }


def resolve_configured_path(path: Path) -> Path:
    if path.is_absolute():
        return path

    candidates = [
        Path.cwd() / path,
        REPO_ROOT / path,
        STUDENT_ROOT / path,
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()

    return (Path.cwd() / path).resolve()


def find_target_for_file(file_path: Path, targets_dir: Path) -> tuple[dict, Path] | None:
    manifest = load_manifest(targets_dir)
    resolved_file = file_path.resolve()

    for target in manifest.get("targets", []):
        target_root = (targets_dir / str(target.get("path", ""))).resolve()

        try:
            resolved_file.relative_to(target_root)
        except ValueError:
            continue

        return target, target_root

    return None


def build_single_file_target(file_path: Path) -> tuple[dict, Path, str]:
    target_info = find_target_for_file(file_path, DEFAULT_TARGETS_DIR)
    if target_info is not None:
        target_entry, target_root = target_info
        return target_entry, target_root, target_entry.get("id", "run_button")

    target_root = file_path.parent
    target_entry = {
        "id": f"single-file-{file_path.stem}",
        "entrypoints": [
            {
                "name": file_path.stem,
                "command": [sys.executable, file_path.name],
                "usage": file_path.name,
                "positionals": [
                    {
                        "name": "arg0",
                        "help": "positional argument",
                        "nargs": "?",
                        "default": None,
                    }
                ],
                "options": [],
            }
        ],
    }
    return target_entry, target_root, target_entry["id"]


def build_single_file_report(
    filepath: Path,
    out_dir: Path,
) -> tuple[dict, list[dict]]:
    target_entry, target_root, target_id = build_single_file_target(filepath)

    analyzer = TargetAnalyzer(target_root)
    findings = analyzer.analyze_file(filepath)

    report_findings = []
    for index, finding in enumerate(findings, start=1):
        entry = {
            "id": f"{target_id}-{finding['type']}-{index}",
            "target_id": target_id,
            "vulnerability_type": finding["type"],
            "location": {
                "path": finding.get("path", filepath.name),
                "line": finding["line"]
            },
            "description": f"Detected {finding['type']}",
        }

        exploit_ref = generate_exploit(
            finding,
            target_root,
            out_dir,
            target_entry,
        )
        if exploit_ref is not None:
            entry["exploit"] = exploit_ref

        report_findings.append(entry)

    report = {
        "schema_version": "1.0",
        "findings": report_findings,
    }
    return report, findings

def run_configured_single_file() -> int:
    file_path = RUN_FILE_PATH

    if not file_path.exists():
        print(f"Error: configured RUN_FILE_PATH does not exist: {file_path}")
        return 1

    if file_path.suffix != ".py":
        print(f"Error: configured RUN_FILE_PATH must point to a .py file: {file_path}")
        return 1

    analyzer = TargetAnalyzer(file_path.parent)
    findings = analyzer.analyze_file(file_path)

    print(f"Analyzed: {file_path}")
    print(f"Findings: {len(findings)}")
    
    for finding in findings:
        finding_path = finding.get("path", str(file_path.relative_to(file_path.parent)))
        print(
            f"  Line {finding['line']:4d} | {finding['type']:25s} | "
            f"{finding_path}"
        )

    return 0


def main() -> int:

    if len(sys.argv) > 1 and sys.argv[1] not in {"file", "targets", "-h", "--help"}:
        # Backward-compatible CLI mode expected by the Makefile:
        # analyze <targets_dir> <out_dir> [single_target_folder]
        legacy_parser = argparse.ArgumentParser(
            description="Taint-flow vulnerability analyzer with control-flow support."
        )
        legacy_parser.add_argument("targets", type=Path, help="Path to targets directory")
        legacy_parser.add_argument("out", type=Path, help="Output directory for report.json")
        legacy_parser.add_argument(
            "single_target_folder",
            nargs="?",
            default=None,
            help="Optional target folder/id to analyze",
        )
        legacy_args = legacy_parser.parse_args()

        legacy_args.out.mkdir(parents=True, exist_ok=True)

        report = analyze(
            legacy_args.targets,
            legacy_args.out,
            legacy_args.single_target_folder,
        )

        (legacy_args.out / "report.json").write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

        findings = report.get("findings", [])
        print(f"Analysis complete. Found {len(findings)} vulnerabilities.")
        print(f"Report written to: {legacy_args.out / 'report.json'}")
        return 0

    parser = argparse.ArgumentParser(
        description="Taint-flow vulnerability analyzer with control-flow support."
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Subcommand: analyze a single file
    single_parser = subparsers.add_parser(
        "file",
        help="Analyze a single Python file for vulnerabilities",
    )
    single_parser.add_argument("filepath", type=Path, help="Path to Python file to analyze")

    # Subcommand: analyze targets directory with manifest
    targets_parser = subparsers.add_parser(
        "targets",
        help="Analyze all targets in a directory (requires manifest.json)",
    )
    targets_parser.add_argument("targets", type=Path, help="Path to targets directory")
    targets_parser.add_argument(
        "out",
        type=Path,
        help="Output directory for report.json",
    )
    targets_parser.add_argument(
        "single_target_folder",
        nargs="?",
        default=None,
        help="Optional target folder/id to analyze",
    )

    args = parser.parse_args()

    if len(sys.argv) == 1:
        # Run button mode: analyze single file and generate report
        filepath = resolve_configured_path(RUN_FILE_PATH)
        out_dir = Path("out_run")

        if not filepath.exists():
            print(f"Error: configured RUN_FILE_PATH does not exist: {filepath}")
            return 1

        if filepath.suffix != ".py":
            print(f"Error: configured RUN_FILE_PATH must point to a .py file: {filepath}")
            return 1

        out_dir.mkdir(parents=True, exist_ok=True)
        report, findings = build_single_file_report(filepath, out_dir)

        (out_dir / "report.json").write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

        print(f"Analyzed: {filepath}")
        print(f"Found {len(findings)} vulnerabilities")
        print(f"Report written to: {out_dir / 'report.json'}")
        print("-" * 70)
    
    elif args.command == "targets":
        # Manifest-based analysis mode
        args.out.mkdir(parents=True, exist_ok=True)

        report = analyze(args.targets, args.out, args.single_target_folder)

        (args.out / "report.json").write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

        findings = report.get("findings", [])
        print(f"Analysis complete. Found {len(findings)} vulnerabilities.")
        print(f"Report written to: {args.out / 'report.json'}")

        return 0

    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())