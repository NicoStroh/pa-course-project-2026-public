from __future__ import annotations

import argparse
import json
from pathlib import Path
from target import TargetAnalyzer

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

    findings = analyzer.analyze_file(Path("student/targets/toy_command_runner/toybackup/cli.py"))

    for finding in findings:
        print(finding)