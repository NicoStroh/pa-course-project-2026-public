from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from shared.validation.json_validation import load_json, validate_instance, load_schema


def load_manifest(targets_dir: Path) -> dict[str, Any]:
    manifest_path = targets_dir / "manifest.json"
    manifest = load_json(manifest_path)
    errors = validate_instance(manifest, load_schema("target_manifest.schema.json"))
    if errors:
        joined = "; ".join(errors)
        raise ValueError(f"invalid target manifest {manifest_path}: {joined}")
    return manifest


def targets_by_id(targets_dir: Path) -> dict[str, dict[str, Any]]:
    manifest = load_manifest(targets_dir)
    return {target["id"]: target for target in manifest["targets"]}


def target_root(targets_dir: Path, target: dict[str, Any]) -> Path:
    root = (targets_dir / target["path"]).resolve()
    targets_root = targets_dir.resolve()
    if not root.is_relative_to(targets_root):
        raise ValueError(f"target path escapes target directory: {target['path']}")
    return root


def env_for_target(targets_dir: Path, target: dict[str, Any]) -> dict[str, str]:
    root = target_root(targets_dir, target)
    pythonpath_entries = [root / entry for entry in target.get("pythonpath", ["."])]
    existing = os.environ.get("PYTHONPATH")
    pythonpath = os.pathsep.join(str(entry) for entry in pythonpath_entries)
    if existing:
        pythonpath = os.pathsep.join([pythonpath, existing])
    return {
        "TARGET_ROOT": str(root),
        "PYTHONPATH": pythonpath,
    }
