from __future__ import annotations

import argparse

from tiny_sql_app.search import search_customers


def main() -> int:
    parser = argparse.ArgumentParser(description="Search customer records.")
    parser.add_argument("term", nargs="?", default="alice")
    args = parser.parse_args()
    for name, email in search_customers(args.term):
        print(f"{name} <{email}>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
