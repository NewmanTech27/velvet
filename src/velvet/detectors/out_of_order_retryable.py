"""`out-of-order-retryable` detector (spec/detectors-catalog.md §7.23 —
normative).

(Arbitrum-specific.)  Flags functions that create two or more retryable
tickets in one L1 transaction under the assumption they execute on L2 in
order or atomically.  Retryable tickets are independent messages: each can
fail, expire, or be redeemed out of order, so L2 logic that depends on their
sequencing breaks.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_f_utils import unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import HighLevelCall

#: Arbitrum inbox entry point that creates a retryable ticket.
_CREATE_RETRYABLE_TICKET = "createRetryableTicket"


class OutOfOrderRetryable(Detector):
    """Detect multiple retryable tickets created in one transaction."""

    RULE = "out-of-order-retryable"
    TITLE = "Multiple retryable tickets assumed to execute in order"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#out-of-order-retryable",
        title="Multiple retryable tickets assumed to execute in order",
        description=(
            "A function creates two or more Arbitrum retryable tickets whose "
            "L2 effects have ordering dependencies. Retryable tickets are "
            "independent messages: each can fail, expire, or be redeemed out "
            "of order, so L2 logic that depends on their sequencing breaks."
        ),
        exploit_scenario=(
            "claimThenUnstake() creates one ticket to claim rewards and a "
            "second to unstake; the unstake ticket is redeemed first (or the "
            "claim expires), destroying the rewards state the first step "
            "relied on."
        ),
        recommendation=(
            "Never rely on retryable ticket ordering or success; bundle "
            "dependent steps into a single ticket or make each step "
            "independently safe."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            call_nodes = []
            for node in function.nodes:
                for op in node.ir_operations:
                    if (
                        isinstance(op, HighLevelCall)
                        and op.function_name == _CREATE_RETRYABLE_TICKET
                    ):
                        call_nodes.append(node)
                        break  # one entry per node holding a ticket creation
            if len(call_nodes) < 2:
                continue
            results.append(
                self.finding(
                    [
                        call_nodes[0],
                        " creates ",
                        str(len(call_nodes)),
                        " retryable tickets in ",
                        function,
                        "; their L2 execution order is not guaranteed",
                    ]
                )
            )
        return results
