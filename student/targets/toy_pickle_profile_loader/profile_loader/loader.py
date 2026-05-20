from __future__ import annotations

import base64
import pickle
from typing import Any


SAFE_PROFILE_B64 = "gASVJAAAAAAAAAB9lCiMBHVzZXKUjAVhbGljZZSMBHJvbGWUjAZyZWFkZXKUdS4="


def load_profile(encoded_snapshot: str) -> Any:
    raw_snapshot = base64.b64decode(encoded_snapshot)
    return pickle.loads(raw_snapshot)
