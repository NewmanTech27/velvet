"""`shadowing-abstract` detector (spec/detectors-catalog.md §7.17 —
normative).

A derived contract redeclares a state variable of an abstract base
contract.  The two variables occupy different storage slots, so reads and
writes silently split: the base's functions observe the base slot while the
derived contract uses its own — updates through one are invisible to the
other.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class ShadowingAbstract(Detector):
    """Detect state variables shadowing an abstract base's state variable."""

    RULE = "shadowing-abstract"
    TITLE = "State variable shadows an abstract contract's variable"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#shadowing-abstract",
        title="State variable shadows an abstract contract's variable",
        description=(
            "A derived contract redeclares a state variable declared in an "
            "abstract base. The two occupy different storage slots, so the "
            "base's logic and the derived contract read and write different "
            "copies of what looks like one variable."
        ),
        exploit_scenario=(
            "abstract Base declares uint256 rate; Market is Base redeclares "
            "uint256 rate; Base.computeFee uses Base.rate while Market.set "
            "updates Market.rate — the fee logic sees a stale value."
        ),
        recommendation=(
            "Rename the derived variable or use the inherited one (with a "
            "setter in the abstract base)."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts:
            if not contract.inheritance:
                continue
            for var in contract.state_variables_shadowed:
                bases = [
                    base
                    for base in contract.inheritance
                    if base.is_abstract
                    and any(v.name == var.name for v in base.state_variables)
                ]
                if not bases:
                    continue
                results.append(
                    self.finding(
                        [
                            var,
                            " shadows the state variable of abstract "
                            "contract(s) ",
                            ", ".join(base.name for base in bases),
                        ]
                    )
                )
        return results
