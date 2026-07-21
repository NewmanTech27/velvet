"""`msg-value-loop` detector (spec/detectors-catalog.md §7.12 — normative).

Flags reads of ``msg.value`` inside a loop body or loop condition in a
payable function.  ``msg.value`` is fixed for the whole transaction, so
crediting or spending it once per iteration multi-counts the same Ether:
depositing 1 ether with ten receivers creates ten ether of internal
credit.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.variables import SolidityVariable
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


def _reads_msg_value(operation: object) -> bool:
    """True when the op directly reads the ``msg.value`` builtin."""
    for variable in getattr(operation, "read", []):
        if isinstance(variable, SolidityVariable) and variable.name == "msg.value":
            return True
    return False


class MsgValueLoop(Detector):
    """Detect ``msg.value`` read inside a loop."""

    RULE = "msg-value-loop"
    TITLE = "msg.value inside a loop"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#msg-value-loop",
        title="msg.value inside a loop",
        description=(
            "msg.value keeps the same value for the whole transaction; "
            "reading it inside a loop credits or spends the full amount "
            "once per iteration, minting unbacked internal balance."
        ),
        exploit_scenario=(
            "fund(address[] receivers) loops doing "
            "credit[receivers[i]] += msg.value; Alice deposits 1 ether "
            "with 10 receivers and withdraws 10 ether of credit."
        ),
        recommendation=(
            "Pass an explicit per-recipient amounts array and require "
            "sum(amounts) == msg.value, or read msg.value once outside "
            "the loop into a bounded per-iteration share."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.available_functions_from_inheritances():
                if not function.payable or not function.is_implemented:
                    continue
                if function.is_constructor:
                    continue
                for node in function.nodes:
                    if not node.is_inside_loop:
                        continue
                    if not any(_reads_msg_value(op) for op in node.ir_operations):
                        continue
                    results.append(
                        self.finding(
                            [
                                node,
                                " reads msg.value inside a loop in ",
                                function,
                                "; the same Ether is accounted once per "
                                "iteration",
                            ]
                        )
                    )
        return results
