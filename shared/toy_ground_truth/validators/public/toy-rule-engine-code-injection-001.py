#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


exploit = Path(os.environ["EXPLOIT_PATH"])
marker = Path(os.environ["EXPLOIT_MARKER"])
completed = subprocess.run([str(exploit)], text=True, capture_output=True, check=False)
print(completed.stdout, end="")
print(completed.stderr, end="", file=sys.stderr)
raise SystemExit(0 if marker.exists() else 1)
