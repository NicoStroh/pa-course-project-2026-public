from __future__ import annotations

import ast
from typing import Dict, List, Set


class BasicBlock:
    def __init__(self, id: int) -> None:
        self.id = id
        self.stmts: List[ast.AST] = []
        self.succs: Set[int] = set()
        self.preds: Set[int] = set()

    def add_stmt(self, stmt: ast.AST) -> None:
        self.stmts.append(stmt)


class CFG:
    def __init__(self) -> None:
        self.blocks: Dict[int, BasicBlock] = {}
        self.entry: int | None = None
        self.exit: int | None = None

    def new_block(self) -> BasicBlock:
        bid = len(self.blocks) + 1
        b = BasicBlock(bid)
        self.blocks[bid] = b
        return b

    def add_edge(self, a: int, b: int) -> None:
        self.blocks[a].succs.add(b)
        self.blocks[b].preds.add(a)


class CFGBuilder:
    """Simple intraprocedural CFG builder.

    Produces a node-per-basic-block CFG. It is intentionally conservative
    and focuses on common constructs (`If`, `For`, `While`, `Return`).
    The resulting graph is sufficient for computing postdominators and
    control dependencies in later steps.
    """

    def build(self, func: ast.FunctionDef) -> CFG:
        self.cfg = CFG()
        # control_deps maps a block id (condition/header) to a set of block ids
        # that are control-dependent on it (blocks inside then/else or loop body).
        self.cfg.control_deps: Dict[int, Set[int]] = {}
        entry = self.cfg.new_block()
        self.cfg.entry = entry.id

        # start with entry as the current "previous" list
        last_blocks = [entry.id]

        for stmt in func.body:
            last_blocks = self._process_stmt(stmt, last_blocks)

        # create exit block and link any remaining last_blocks to it
        exit_block = self.cfg.new_block()
        self.cfg.exit = exit_block.id

        for lb in last_blocks:
            self.cfg.add_edge(lb, exit_block.id)

        return self.cfg

    def _process_stmt(self, stmt: ast.stmt, prev: List[int]) -> List[int]:
        # Simple statements: create a block with the statement and link
        if isinstance(stmt, (ast.Assign, ast.Expr, ast.AugAssign, ast.AnnAssign)):
            b = self.cfg.new_block()
            b.add_stmt(stmt)
            for p in prev:
                self.cfg.add_edge(p, b.id)
            return [b.id]

        if isinstance(stmt, ast.Return):
            b = self.cfg.new_block()
            b.add_stmt(stmt)
            for p in prev:
                self.cfg.add_edge(p, b.id)
            # Return ends control flow: no fallthrough
            return []

        if isinstance(stmt, ast.If):
            # condition block
            cond = self.cfg.new_block()
            cond.add_stmt(stmt.test)
            for p in prev:
                self.cfg.add_edge(p, cond.id)

            # then branch
            then_prev = [cond.id]
            # record blocks count before processing then branch
            n_before_then = len(self.cfg.blocks)
            for s in stmt.body:
                then_prev = self._process_stmt(s, then_prev)
            n_after_then = len(self.cfg.blocks)
            then_created = [i for i in range(n_before_then + 1, n_after_then + 1)]

            # else branch
            else_prev = [cond.id]
            n_before_else = len(self.cfg.blocks)
            for s in stmt.orelse:
                else_prev = self._process_stmt(s, else_prev)
            n_after_else = len(self.cfg.blocks)
            else_created = [i for i in range(n_before_else + 1, n_after_else + 1)]

            # record control dependencies: cond -> blocks created in then/else
            created = set(then_created + else_created)
            if created:
                self.cfg.control_deps[cond.id] = created

            # If no body/orelse, fallthrough is the cond node
            result_last: List[int] = []
            if then_prev:
                result_last.extend(then_prev)
            else:
                result_last.append(cond.id)

            if else_prev:
                result_last.extend(else_prev)
            else:
                result_last.append(cond.id)

            return result_last

        if isinstance(stmt, (ast.For, ast.While)):
            # loop condition / header block
            header = self.cfg.new_block()
            # store the loop's conditional expression (iter/test) for easier analysis
            if isinstance(stmt, ast.For):
                header.add_stmt(stmt.iter)
            elif isinstance(stmt, ast.While):
                header.add_stmt(stmt.test)
            else:
                header.add_stmt(stmt)
            for p in prev:
                self.cfg.add_edge(p, header.id)

            # body
            body_prev = [header.id]
            n_before_body = len(self.cfg.blocks)
            for s in stmt.body:
                body_prev = self._process_stmt(s, body_prev)
            n_after_body = len(self.cfg.blocks)
            body_created = [i for i in range(n_before_body + 1, n_after_body + 1)]

            # link body back to header to represent loop
            for b in body_prev:
                self.cfg.add_edge(b, header.id)

            # record control dependencies: header -> blocks created in body
            if body_created:
                self.cfg.control_deps[header.id] = set(body_created)

            # orelse executes when loop exits normally
            orelse_prev = [header.id]
            for s in stmt.orelse:
                orelse_prev = self._process_stmt(s, orelse_prev)

            # fallthrough from header (loop exit) is header (if no orelse blocks)
            result_last = []
            if orelse_prev:
                result_last.extend(orelse_prev)
            else:
                result_last.append(header.id)

            return result_last

        # Fallback: treat unknown compound stmts as single block
        b = self.cfg.new_block()
        b.add_stmt(stmt)
        for p in prev:
            self.cfg.add_edge(p, b.id)
        return [b.id]


def build_cfg_for_function(func: ast.FunctionDef) -> CFG:
    return CFGBuilder().build(func)
