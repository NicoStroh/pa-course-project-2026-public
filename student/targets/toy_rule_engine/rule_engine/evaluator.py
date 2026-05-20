from __future__ import annotations


def evaluate_discount(rule_expression: str, subtotal: float) -> float:
    context = {
        "subtotal": subtotal,
        "min": min,
        "max": max,
        "round": round,
    }
    return float(eval(rule_expression, {}, context))
