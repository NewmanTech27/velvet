"""``entry-points`` printer — state-changing externally callable functions.

Spec: spec/printers-and-tools.md §A.12.  For each contract, the externally
reachable (``external``/``public``), non-``view``/``pure`` functions with the
state variables they read and write.  Constructors are excluded: they are not
callable by an arbitrary caller after deployment.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.printers.base import Printer


class EntryPointsPrinter(Printer):
    RULE = "entry-points"
    TITLE = "State-changing externally callable functions and their variables"

    def output(self) -> None:
        for contract in self.compilation_unit.contracts:
            entry_points = [
                function
                for function in contract.functions_entry_points
                if not function.view
                and not function.pure
                and not function.is_constructor
            ]
            self.info(f"+ Contract {contract.name}")
            if not entry_points:
                self.info("  (no state-changing entry points)")
                continue
            for function in entry_points:
                self.info(f"  - {function.signature}")
                read = ", ".join(v.name for v in function.state_variables_read)
                written = ", ".join(v.name for v in function.state_variables_written)
                self.info(f"      read: {read if read else '(none)'}")
                self.info(f"      written: {written if written else '(none)'}")
