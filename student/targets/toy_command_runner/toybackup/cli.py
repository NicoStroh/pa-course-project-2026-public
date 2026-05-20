from __future__ import annotations

import sys

from toybackup.runner import run_backup_job


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    job_name = args[0] if args else "daily"
    return run_backup_job(job_name)


if __name__ == "__main__":
    raise SystemExit(main())
