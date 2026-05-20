from __future__ import annotations

import argparse

from profile_loader.loader import SAFE_PROFILE_B64, load_profile


def main() -> int:
    parser = argparse.ArgumentParser(description="Load a profile snapshot.")
    parser.add_argument("payload", nargs="?", default=SAFE_PROFILE_B64)
    args = parser.parse_args()
    print(load_profile(args.payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
