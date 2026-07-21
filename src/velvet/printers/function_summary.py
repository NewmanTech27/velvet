"""``function-summary`` printer — per-function detail tables.

Spec: spec/printers-and-tools.md §A.7.  For each contract: the contract
variables, the inheritance list, a table of functions with columns
``Function | Visibility | Modifiers | Read | Write | Internal Calls |
External Calls`` and a second table for the declared modifiers with columns
``Modifiers | Visibility | Read | Write | Internal Calls | External Calls``.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.core.variables import SolidityVariable
from velvet.printers._utils import function_label, render_table, value_name
from velvet.printers.base import Printer


def _reads(function: Any) -> str:
    """State variables + special variables (msg.sender, ...) read."""
    names = [v.name for v in function.state_variables_read]
    names += [
        v.name
        for v in function.variables_read
        if isinstance(v, SolidityVariable)
    ]
    return "\n".join(dict.fromkeys(names))


def _writes(function: Any) -> str:
    return "\n".join(v.name for v in function.state_variables_written)


def _internal_calls(function: Any) -> str:
    from velvet.ir.operations import InternalDynamicCall

    labels = []
    for op in function.internal_calls:
        target = op.function
        labels.append(target.signature if target is not None else op.function_name)
    for op in function.library_calls:
        dest = value_name(op.destination)
        labels.append(f"{dest}.{op.function_name}")
    for node in function.all_nodes:  # internal dynamic dispatch targets
        for op in node.ir_operations:
            if isinstance(op, InternalDynamicCall):
                labels.append(value_name(op.function_variable))
    return "\n".join(dict.fromkeys(labels))


def _external_calls(function: Any) -> str:
    labels = []
    for op in function.high_level_calls:
        labels.append(f"{value_name(op.destination)}.{op.function_name}")
    for op in function.low_level_calls:
        labels.append(f"{value_name(op.destination)}.{op.function_name}")
    return "\n".join(dict.fromkeys(labels))


class FunctionSummaryPrinter(Printer):
    RULE = "function-summary"
    TITLE = "Per-function summary: visibility, modifiers, reads, writes, calls"

    def output(self) -> None:
        for contract in self.compilation_unit.contracts:
            self.info(f"Contract {contract.name}")
            variables = ", ".join(v.name for v in contract.state_variables_ordered)
            self.info(f"Contract vars: {variables if variables else '(none)'}")
            bases = ", ".join(b.name for b in contract.inheritance)
            self.info(f"Inheritances: {bases if bases else '(none)'}")
            if contract.functions:
                rows = [
                    [
                        function_label(function),
                        function.visibility,
                        "\n".join(m.name for m in function.modifiers),
                        _reads(function),
                        _writes(function),
                        _internal_calls(function),
                        _external_calls(function),
                    ]
                    for function in contract.functions
                ]
                self.info(
                    render_table(
                        [
                            "Function",
                            "Visibility",
                            "Modifiers",
                            "Read",
                            "Write",
                            "Internal Calls",
                            "External Calls",
                        ],
                        rows,
                    )
                )
            if contract.modifiers:
                rows = [
                    [
                        modifier.signature,
                        modifier.visibility,
                        _reads(modifier),
                        _writes(modifier),
                        _internal_calls(modifier),
                        _external_calls(modifier),
                    ]
                    for modifier in contract.modifiers
                ]
                self.info(
                    render_table(
                        [
                            "Modifiers",
                            "Visibility",
                            "Read",
                            "Write",
                            "Internal Calls",
                            "External Calls",
                        ],
                        rows,
                    )
                )
