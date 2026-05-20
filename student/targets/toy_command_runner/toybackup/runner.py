from __future__ import annotations

import os
from pathlib import Path


BACKUP_ROOT = Path(__file__).resolve().parents[1] / "backups"


def list_jobs() -> list[str]:
    if not BACKUP_ROOT.exists():
        return []
    return sorted(path.name for path in BACKUP_ROOT.iterdir() if path.is_dir())


def run_backup_job(job_name: str) -> int:
    BACKUP_ROOT.mkdir(exist_ok=True)
    command = f"echo running backup for {job_name}"
    return os.system(command)
