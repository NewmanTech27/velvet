"""`unchecked-lowlevel` detector (spec/detectors-catalog.md §7.25 —
normative).

Flags low-level calls (``call``/``delegatecall``/``staticcall``/``callcode``)
whose boolean success value is discarded: the success slot of the returned
tuple is never unpacked (not captured), or the captured flag never reaches a
condition, a ``require``/``assert`` guard, an event (not logged) or a return
(forwarded to the caller).  Low-level calls do not revert on failure, so
execution continues as if the interaction succeeded (SWC-104).

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_b_utils import terminal_consumers
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import (
    Condition,
    EventCall,
    LowLevelCall,
    Operation,
    Return,
    SolidityCall,
    Unpack,
)

_GUARD_BUILTINS = ("require", "assert")


class UncheckedLowlevel(Detector):
    """Detect low-level calls whose success flag is discarded."""

    RULE = "unchecked-lowlevel"
    TITLE = "Unchecked low-level call return value"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#unchecked-lowlevel",
        title="Unchecked low-level call return value",
        description=(
            "The success flag returned by a low-level call is ignored; "
            "low-level calls return false on failure instead of reverting, "
            "so execution continues as if the interaction succeeded "
            "(SWC-104)."
        ),
        exploit_scenario=(
            "pay(employee, salary) runs employee.call{value: salary}(\"\") "
            "without checking the result; the payment silently fails while "
            "the contract records it as done."
        ),
        recommendation=(
            "Capture and check the success flag "
            "((bool ok, ) = ...; require(ok);), or deliberately log failures "
            "if asynchronous failure handling is intended."
        ),
    )

    @staticmethod
    def _is_handled(consumers: list[Operation]) -> bool:
        """The success flag is checked, logged, or forwarded to the caller."""
        for op in consumers:
            if isinstance(op, (Condition, EventCall, Return)):
                return True
            if isinstance(op, SolidityCall) and op.function.name in _GUARD_BUILTINS:
                return True
        return False

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        seen_functions: set[int] = set()
        for contract in self.compilation_unit.contracts_derived:
            functions = list(contract.available_functions_from_inheritances())
            functions += list(contract.all_modifiers())
            for function in functions:
                if id(function) in seen_functions:
                    continue
                seen_functions.add(id(function))
                # Success-flag holders of every low-level-call tuple in this
                # function (UNPACK of the tuple at index 0).
                unpacks = [
                    op
                    for op in function.all_ir_operations
                    if isinstance(op, Unpack)
                ]
                for node in function.all_nodes:
                    for op in node.ir_operations:
                        if not isinstance(op, LowLevelCall):
                            continue
                        holders = [
                            unpack.lvalue
                            for unpack in unpacks
                            if unpack.tuple_variable is op.lvalue
                            and unpack.index == 0
                        ]
                        if holders:
                            consumers = terminal_consumers(function, holders)
                            if self._is_handled(consumers):
                                continue
                        results.append(
                            self.finding(
                                [
                                    node,
                                    " ignores the success value of a "
                                    f"low-level {op.function_name} call in ",
                                    function,
                                ]
                            )
                        )
        return results
