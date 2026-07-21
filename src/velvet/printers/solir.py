"""``solir`` printer — textual dump of the SolIR of every function.

Spec: spec/printers-and-tools.md §A.15 / architecture.md §9 (``solir`` /
``solir-ssa`` IR dumps).  One canonical op string per line, grouped by
function and by CFG node.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.printers.base import Printer


def dump_ir(function: Any, *, ssa: bool) -> list[str]:
    """Render one function's IR (or SSA IR) as text lines."""
    lines = [f"Function: {function.canonical_name}"]
    if not function.is_implemented:
        lines.append("\t(no body)")
        return lines
    for node in function.nodes:
        lines.append(f"\tNode {node.node_id}: {node}")
        ops = node.ir_operations_ssa if ssa else node.ir_operations
        for op in ops:
            lines.append(f"\t\t{op}")
    return lines


class SolirPrinter(Printer):
    RULE = "solir"
    TITLE = "SolIR dump (one op per line, grouped by function/node)"

    SSA = False

    def output(self) -> None:
        for contract in self.compilation_unit.contracts:
            self.info(f"Contract: {contract.name}")
            for function in contract.functions_and_modifiers:
                for line in dump_ir(function, ssa=self.SSA):
                    self.info(line)
        top_level = self.compilation_unit.top_level_functions
        if top_level:
            self.info("Top-level functions:")
            for function in top_level:
                for line in dump_ir(function, ssa=self.SSA):
                    self.info(line)
