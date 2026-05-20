from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_schema(name: str) -> dict[str, Any]:
    return load_json(REPO_ROOT / "shared" / "schemas" / name)


def validate_instance(instance: Any, schema: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(instance), key=lambda err: list(err.path))
    messages = []
    for error in errors:
        location = "/".join(str(part) for part in error.absolute_path)
        prefix = f"{location}: " if location else ""
        messages.append(prefix + error.message)
    return messages


def validate_json_file(path: Path, schema_name: str) -> list[str]:
    return validate_instance(load_json(path), load_schema(schema_name))
