"""`incorrect-equality` detector (spec/detectors-catalog.md §7.14 —
normative).

Flags strict equality (``==`` / ``!=``) against a balance.  Ether can be
forced into a contract without running its code (``selfdestruct``
beneficiary, coinbase reward, pre-computed address funding), so
``address(this).balance == goal`` can be permanently skipped; token
balances (``balanceOf``) have analogous donation attacks.  The balance
origin is chased through copies, so locals caching a balance are covered.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_e_utils import balance_like_sources, unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import Binary


class IncorrectEquality(Detector):
    """Detect strict equality used against a balance."""

    RULE = "incorrect-equality"
    TITLE = "Strict equality against a balance"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#incorrect-equality",
        title="Dangerous strict equality on a balance",
        description=(
            "A strict equality comparison (== or !=) where one operand is "
            "an Ether/token balance; balances can be shifted without the "
            "contract's cooperation, so the equality can be permanently "
            "skipped."
        ),
        exploit_scenario=(
            "finalize() requires address(this).balance == GOAL; an "
            "attacker force-sends 1 wei via selfdestruct and the crowdfund "
            "can never be finalized."
        ),
        recommendation="Use >= / <= range comparisons for balance thresholds.",
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            for node in function.nodes:
                for op in node.ir_operations:
                    if not (isinstance(op, Binary) and op.operator in ("==", "!=")):
                        continue
                    if not (
                        balance_like_sources(function, op.left)
                        or balance_like_sources(function, op.right)
                    ):
                        continue
                    results.append(
                        self.finding(
                            [
                                node,
                                f" uses strict equality ({op.operator}) "
                                "against a balance in ",
                                function,
                                "; forced Ether or donations can make the "
                                "check unreachable",
                            ]
                        )
                    )
                    break  # one finding per node
        return results
