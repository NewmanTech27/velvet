"""`reentrancy-benign` detector (spec/detectors-catalog.md §1.4 — normative).

Flags external calls followed by a state write where the written variable is
*not* read on the path leading to the call — it neither gates the call nor
meters a value transfer, so exploitation is equivalent to calling the
function twice. Mostly a code smell that can hide deeper issues.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._reentrancy_common import (
    function_call_contexts,
    iter_analyzable_functions_with_contract,
    natspec_tagged_state_variables,
    non_gating_writes,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class ReentrancyBenign(Detector):
    """Detect reentrancy equivalent to calling the function twice."""

    RULE = "reentrancy-benign"
    TITLE = "Benign reentrancy (non-gating state write after external call)"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#reentrancy-benign",
        title="Benign reentrancy",
        description=(
            "An external call is followed by a write to a state variable "
            "that is not used to gate the call or meter a value transfer, "
            "so re-entering the function has the same effect as two "
            "consecutive legitimate calls."
        ),
        exploit_scenario=(
            "Notifier.ping calls an arbitrary target and increments a "
            "counter only after the call; re-entry merely repeats what a "
            "second call would do anyway."
        ),
        recommendation=(
            "Apply the checks-effects-interactions pattern anyway, or "
            "document that the ordering is intentional."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        safe_vars = natspec_tagged_state_variables(self.compilation_unit)
        for contract, function in iter_analyzable_functions_with_contract(
                self.compilation_unit
            ):
            for context in function_call_contexts(function, safe_vars, contract=contract):
                for var, write_node in non_gating_writes(context):
                    results.append(
                        self.finding(
                            [
                                write_node,
                                " updates ",
                                var,
                                " after an external call (",
                                context.node,
                                ") that does not depend on it in ",
                                function,
                            ]
                        )
                    )
        return results
