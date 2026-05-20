from __future__ import annotations

import argparse

from note_server.files import read_note


def main() -> int:
    parser = argparse.ArgumentParser(description="Read a note by name.")
    parser.add_argument("name", nargs="?", default="welcome.txt")
    args = parser.parse_args()
    print(read_note(args.name), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
