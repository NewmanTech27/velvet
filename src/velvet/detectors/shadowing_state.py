"""`shadowing-state` detector (spec/detectors-catalog.md §7.5 — normative).

Flags a state variable declaration that hides a state variable inherited
from a non-abstract base contract.  The two variables occupy different
storage slots; base-contract functions keep using the base slot, so the
derived contract's "assignment" has no effect on base logic.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.contract import Contract
from velvet.core.variables import StateVariable
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


def _shadowed_in_non_abstract_base(
    contract: Contract, var: StateVariable
) -> list[Contract]:
    """Non-abstract bases of ``contract`` declaring a variable named ``var.name``."""
    return [
        base
        for base in contract.inheritance
        if not base.is_abstract
        and not base.is_interface
        and any(v.name == var.name for v in base.state_variables)
    ]


class ShadowingState(Detector):
    """Detect state variables shadowing an inherited state variable."""

    RULE = "shadowing-state"
    TITLE = "State variable shadowing"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#shadowing-state",
        title="State variable shadowing",
        description=(
            "A derived contract re-declares a state variable that already "
            "exists in a base contract. The two variables occupy different "
            "storage slots; base-contract functions keep using the base "
            "slot, so the derived contract's assignment has no effect on "
            "base logic."
        ),
        exploit_scenario=(
            "Vault re-declares `owner`, shadowing Owned.owner; the "
            "onlyOwner modifier still reads the unset base slot, so the "
            "protected function is reachable by anyone."
        ),
        recommendation=(
            "Remove the duplicate declaration; assign the inherited "
            "variable (via a base constructor or an internal setter)."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts:
            for var in contract.state_variables_shadowed:
                bases = _shadowed_in_non_abstract_base(contract, var)
                if not bases:
                    continue
                base_names = ", ".join(b.name for b in bases)
                results.append(
                    self.finding(
                        [
                            var,
                            f" shadows a state variable inherited from {base_names} in ",
                            contract,
                        ],
                        additional_fields={"shadowed_bases": base_names},
                    )
                )
        return results
