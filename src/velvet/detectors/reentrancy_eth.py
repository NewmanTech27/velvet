"""`reentrancy-eth` detector (spec/detectors-catalog.md §1.1 — normative).

Flags functions where an external, gas-unbounded call that sends Ether to a
not statically trusted address happens *before* a state variable read on the
path to the call is updated (classic checks-effects-interactions violation,
SWC-107).  ``send``/``transfer``-only cases (fixed stipend) and calls moving
no Ether are left to other reentrancy variants.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._reentrancy_common import (
    destination_is_trusted,
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


class ReentrancyEth(Detector):
    """Detect reentrancy that can lead to theft of Ether."""

    RULE = "reentrancy-eth"
    TITLE = "Reentrancy leading to Ether theft"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#reentrancy-eth",
        title="Reentrancy leading to Ether theft",
        description=(
            "A function sends Ether through a gas-unbounded external call to "
            "a potentially attacker-controlled address and only afterwards "
            "updates the state variable that authorized or metered the "
            "transfer (SWC-107). A re-entrant execution observes the stale "
            "state and can withdraw again."
        ),
        exploit_scenario=(
            "Vault.withdraw reads deposits[msg.sender], sends the Ether with "
            "msg.sender.call{value: amount} and zeroes the deposit only after "
            "the call; the attacker's fallback re-enters withdraw and drains "
            "the contract."
        ),
        recommendation=(
            "Apply the checks-effects-interactions pattern (update the state "
            "before the call) and/or guard the function with a reentrancy "
            "mutex."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        safe_vars = natspec_tagged_state_variables(self.compilation_unit)
        for contract, function in iter_analyzable_functions_with_contract(
                self.compilation_unit
            ):
            for context in function_call_contexts(function, safe_vars, contract=contract):
                if not context.sends_eth or context.gas_bounded:
                    continue
                if destination_is_trusted(context):
                    continue
                for var, write_node in gating_writes(context):
                    results.append(
                        self.finding(
                            [
                                context.node,
                                " sends Ether before ",
                                var,
                                " is updated (",
                                write_node,
                                ") in re-enterable function ",
                                function,
                            ]
                        )
                    )
        return results
