from __future__ import annotations

from pathlib import Path


TARGET_ROOT = Path(__file__).resolve().parents[1]
NOTES_DIR = TARGET_ROOT / "notes"


def read_note(name: str) -> str:
    path = NOTES_DIR / name
    return path.read_text(encoding="utf-8")
