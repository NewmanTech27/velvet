"""`unchecked-send` detector (spec/detectors-catalog.md §7.26 — normative).

Flags ``address.send(...)`` whose boolean result is neither checked nor
otherwise consumed.  ``send`` returns ``false`` on failure (out of gas in
the callee, reverting fallback) instead of reverting, so the contract
proceeds as though the payment happened (SWC-104).

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
from velvet.ir.operations import Send


class UncheckedSend(Detector):
    """Detect send() calls whose return value is discarded."""

    RULE = "unchecked-send"
    TITLE = "Unchecked send return value"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#unchecked-send",
        title="Unchecked send return value",
        description=(
            "The return value of address.send is ignored; send returns "
            "false on failure instead of reverting, so the contract "
            "proceeds as though the payment happened (SWC-104)."
        ),
        exploit_scenario=(
            "refund() zeroes the refund balance and calls "
            "payable(msg.sender).send(amt); when the send silently fails "
            "the user's refund is gone forever."
        ),
        recommendation=(
            "Check the return (require(payable(x).send(amt))) or prefer "
            "call with an explicit success check."
        ),
    )

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
                for node in function.all_nodes:
                    for op in node.ir_operations:
                        if not isinstance(op, Send):
                            continue
                        # Flag only when the boolean result is neither
                        # checked nor otherwise consumed.
                        if terminal_consumers(function, [op.lvalue]):
                            continue
                        results.append(
                            self.finding(
                                [
                                    node,
                                    " ignores the return value of send in ",
                                    function,
                                ]
                            )
                        )
        return results
