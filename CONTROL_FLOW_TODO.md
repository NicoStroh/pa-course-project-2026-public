# Control-Flow Analysis Todo

## Goal

Determine whether attacker-controlled inputs (sources) can reach sinks via control-flow (implicit flows), by adding a control-flow analysis to the existing taint analyzer.

## Plan

1. Audit existing analyzers and sources (read `student/analyzer/analyzers.py`, `student/analyzer/taint.py`, `student/analyzer/sources.py`).
2. Design CFG + control-dependency model (intraprocedural first; plan interprocedural extension).
3. Implement intraprocedural CFG builder for Python ASTs (basic blocks + edges).
4. Compute control dependencies per function (post-dominator tree + control-dependency algorithm).
5. Extend taint propagation to include implicit flows via control dependencies.
6. Integrate control-flow taints into sink reachability checks in the analyzer.
7. Test toy examples

## Notes

- Start small: intraprocedural CFG and control-dependency analysis will cover most toy targets.
- Track progress by updating the project's main todo separately from this file.
