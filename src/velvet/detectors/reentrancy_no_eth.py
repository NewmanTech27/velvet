"""`reentrancy-no-eth` detector (spec/detectors-catalog.md §1.3 — normative).

Same structural pattern as `reentrancy-eth` (an external call followed by a
write to a state variable read on the path to the call) but without Ether
being sent on the vulnerable path, so no direct ETH theft — the re-entrant
call can still corrupt application state or bypass a one-shot guard.
Interactions already covered by `reentrancy-eth` are excluded by
construction (they carry Ether).

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._reentrancy_common import (
    function_call_contexts,
    gating_writes,
    iter_analyzable_functions_with_contract,
    natspec_tagged_state_variables,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class ReentrancyNoEth(Detector):
    """Detect reentrancy without Ether movement (state corruption)."""

    RULE = "reentrancy-no-eth"
    TITLE = "Reentrancy without Ether transfer"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#reentrancy-no-eth",
        title="Reentrancy without Ether transfer",
        description=(
            "A function makes an external call that moves no Ether and "
            "updates a state variable read on the path to the call only "
            "afterwards. Re-entering the function observes the stale state "
            "and can corrupt accounting or bypass a one-shot guard."
        ),
        exploit_scenario=(
            "Auction.settle calls an external token contract and sets "
            "settled = true only after the call; a malicious token re-enters "
            "settle and settles the auction a second time."
        ),
        recommendation=(
            "Apply the checks-effects-interactions pattern (set flags and "
            "update state before external calls); consider a reentrancy "
            "guard for functions that must be single-shot."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        safe_vars = natspec_tagged_state_variables(self.compilation_unit)
        for contract, function in iter_analyzable_functions_with_contract(
                self.compilation_unit
            ):
            for context in function_call_contexts(function, safe_vars, contract=contract):
                # Ether-moving interactions belong to reentrancy-eth.
                if context.sends_eth:
                    continue
                for var, write_node in gating_writes(context):
                    results.append(
                        self.finding(
                            [
                                context.node,
                                " is an external call before ",
                                var,
                                " is updated (",
                                write_node,
                                ") in re-enterable function ",
                                function,
                            ]
                        )
                    )
        return results
