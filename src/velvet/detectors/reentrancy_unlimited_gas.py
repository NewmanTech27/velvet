"""`reentrancy-unlimited-gas` detector (spec/detectors-catalog.md §1.6 —
normative).

Same structural pattern as `reentrancy-eth` (an external interaction before
a state update that was read on the path to the interaction) but where the
Ether-moving calls are ``send`` or ``transfer`` — calls with a fixed 2300
gas stipend.  Reentrancy is then limited by the stipend (no unlimited gas
for the re-entering code), so the finding is informational: it is still a
CEI violation and breaks if gas semantics change.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._reentrancy_common import (
    destination_is_trusted,
    function_call_contexts,
    gating_writes,
    iter_analyzable_functions_with_contract,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class ReentrancyUnlimitedGas(Detector):
    """Detect reentrancy limited by the send/transfer gas stipend."""

    RULE = "reentrancy-unlimited-gas"
    TITLE = "Reentrancy limited by the send/transfer gas stipend"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#reentrancy-unlimited-gas",
        title="Reentrancy limited by the send/transfer gas stipend",
        description=(
            "A function sends Ether through send or transfer (fixed 2300 gas "
            "stipend) and updates state read on the path to the call only "
            "afterwards. The stipend blocks unlimited-gas reentrancy today, "
            "but the checks-effects-interactions violation remains fragile "
            "to gas-schedule changes."
        ),
        exploit_scenario=(
            "Vault.withdraw checks balances[msg.sender], then calls "
            "msg.sender.transfer(amount) and only afterwards zeroes the "
            "balance; any future increase of the transfer stipend turns the "
            "function into a full reentrancy-eth exploit."
        ),
        recommendation=(
            "Apply checks-effects-interactions (update state before moving "
            "Ether) even when using send/transfer, or use call with a "
            "reentrancy guard."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract, function in iter_analyzable_functions_with_contract(
                self.compilation_unit
            ):
            contexts = function_call_contexts(function, contract=contract)
            # The catalog scopes the rule to functions whose only Ether-moving
            # calls are send/transfer; an unlimited-gas call in the same
            # function makes the pattern reentrancy-eth instead.
            has_unbounded_eth = any(
                context.sends_eth and not context.gas_bounded for context in contexts
            )
            if has_unbounded_eth:
                continue
            for context in contexts:
                if not (context.sends_eth and context.gas_bounded):
                    continue
                if destination_is_trusted(context):
                    continue
                for var, write_node in gating_writes(context):
                    results.append(
                        self.finding(
                            [
                                context.node,
                                " sends Ether through send/transfer (fixed "
                                "gas stipend) before ",
                                var,
                                " is updated (",
                                write_node,
                                ") in re-enterable function ",
                                function,
                            ]
                        )
                    )
        return results
