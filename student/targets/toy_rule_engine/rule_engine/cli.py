from __future__ import annotations

import argparse

from rule_engine.evaluator import evaluate_discount


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate a checkout discount rule.")
    parser.add_argument("rule", nargs="?", default="subtotal * 0.10")
    parser.add_argument("--subtotal", type=float, default=42.0)
    args = parser.parse_args()
    print(evaluate_discount(args.rule, args.subtotal))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
