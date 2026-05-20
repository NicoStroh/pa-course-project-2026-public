# Toy Rule Engine

This tiny package evaluates pricing rules for a pretend checkout workflow. It
contains exactly one intentional `code_injection` vulnerability.

The vulnerable function is `rule_engine.evaluator.evaluate_discount`. It passes
a user-controlled rule expression directly to `eval`.
