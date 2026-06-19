from __future__ import annotations

import ast
from typing import Set

from cfg import build_cfg_for_function
from taint import TaintAnalyzer


def propagate_implicit_taints(
    func: ast.FunctionDef,
    tainted_variables: Set[str],
    function_summaries: dict,
) -> Set[str]:
    """Given a FunctionDef and current explicit `tainted_variables`,
    return a set of variables that become implicitly tainted due to
    control dependencies on tainted conditions.

    This is intraprocedural and conservative: if a condition expression
    in a block is tainted, all `ast.Name` assignment targets in blocks
    control-dependent on that condition are considered implicitly tainted.
    """

    implicit: Set[str] = set()

    cfg = build_cfg_for_function(func)

    # cfg.control_deps maps condition block id -> set(block ids)
    for cond_bid, dependent_bids in getattr(cfg, "control_deps", {}).items():
        # look up the condition expression(s) stored in the block
        cond_block = cfg.blocks.get(cond_bid)
        if not cond_block:
            continue

        cond_tainted = False
        for stmt in cond_block.stmts:
            try:
                if TaintAnalyzer.expression_is_tainted(
                    stmt,
                    tainted_variables,
                    function_summaries,
                ):
                    cond_tainted = True
                    break
            except Exception:
                # be conservative: if evaluation fails, assume not tainted
                continue

        if not cond_tainted:
            continue

        # condition is tainted; collect assignment targets in dependent blocks
        for bid in dependent_bids:
            block = cfg.blocks.get(bid)
            if not block:
                continue

            for s in block.stmts:
                # find simple assignments `name = ...`
                if isinstance(s, ast.Assign):
                    for tgt in s.targets:
                        if isinstance(tgt, ast.Name):
                            implicit.add(tgt.id)
                elif isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name):
                    implicit.add(s.target.id)
                elif isinstance(s, ast.AugAssign) and isinstance(s.target, ast.Name):
                    implicit.add(s.target.id)

    return implicit
