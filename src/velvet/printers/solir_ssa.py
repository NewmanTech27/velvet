"""``solir-ssa`` printer — textual dump of the SSA form of the SolIR.

Same layout as ``solir`` (see spec/printers-and-tools.md §A.15), rendered
from each node's ``ir_operations_ssa``.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.printers.solir import SolirPrinter


class SolirSsaPrinter(SolirPrinter):
    RULE = "solir-ssa"
    TITLE = "SolIR-SSA dump (one op per line, grouped by function/node)"

    SSA = True
