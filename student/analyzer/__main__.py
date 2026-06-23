from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from target import TargetAnalyzer
from exploit_generation import generate_exploit


# One-click run configuration (used when this file is run with no CLI args).
# Change this path to the file you want to analyze from the Run button.
RUN_FILE_PATH = Path("student/targets/fossier/src/fossier/cli.py")

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
    # Run-button friendly mode: no args means "analyze RUN_FILE_PATH".
    if len(sys.argv) == 1:
        return run_configured_single_file()

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

    args = parser.parse_args()

    if args.command == "file":
        # Single-file analysis mode
        if not args.filepath.exists():
            print(f"Error: File not found: {args.filepath}")
            return 1

        if not args.filepath.suffix == ".py":
            print(f"Error: File must be a Python file (.py): {args.filepath}")
            return 1

        # Analyze the single file
        analyzer = TargetAnalyzer(args.filepath.parent)
        findings = analyzer.analyze_file(args.filepath)

        if not findings:
            print(f"[OK] No vulnerabilities found in {args.filepath}")
            return 0

        print(f"Found {len(findings)} vulnerabilities in {args.filepath}:")
        print("-" * 70)

        for finding in findings:
            finding_path = finding.get("path", str(args.filepath.relative_to(args.filepath.parent)))
            print(
                f"  Line {finding['line']:4d} | {finding['type']:25s} | "
                f"{finding_path}"
            )

        return 0

    elif args.command == "targets":
        # Manifest-based analysis mode
        args.out.mkdir(parents=True, exist_ok=True)

        report = analyze(args.targets, args.out)

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