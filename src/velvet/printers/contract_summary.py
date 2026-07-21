"""``contract-summary`` printer — quick per-contract overview.

Spec: spec/printers-and-tools.md §A.6.  For each contract a header line
``+ Contract <Name>`` followed by one ``- <name> (<visibility>)`` line per
function.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.printers._utils import function_label
from velvet.printers.base import Printer


class ContractSummaryPrinter(Printer):
    RULE = "contract-summary"
    TITLE = "Quick per-contract overview (functions + visibility)"

    def output(self) -> None:
        for contract in self.compilation_unit.contracts:
            kind = "" if contract.kind.value == "contract" else f" [{contract.kind.value}]"
            self.info(f"+ Contract {contract.name}{kind}")
            for function in contract.functions:
                self.info(f"- {function_label(function)} ({function.visibility})")
            if not contract.functions:
                self.info("- (no functions)")
