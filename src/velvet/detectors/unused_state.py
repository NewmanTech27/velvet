"""`unused-state` detector (spec/detectors-catalog.md §8.16 — normative).

Flags state variables that are never read by any function, modifier or
inline initializer in the contract's inheritance family.  Public variables
are excluded (the compiler-generated getter is an implicit reader), as are
variables required for interface/override conformance.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.contract import Contract
from velvet.core.variables import StateVariable
from velvet.detectors._state_family import state_variables_read_in_family
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


def _used_for_override_conformance(contract: Contract, var: StateVariable) -> bool:
    """True when a ``public`` variable implements an inherited getter (an
    interface/abstract base declares a function of the same name)."""
    if var.visibility != "public":
        return False
    for base in contract.inheritance:
        if base.is_interface or base.is_abstract:
            if any(func.name == var.name for func in base.functions):
                return True
    return False


class UnusedState(Detector):
    """Detect state variables that are never read."""

    RULE = "unused-state"
    TITLE = "Unused state variable"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#unused-state",
        title="Unused state variables",
        description=(
            "State variables that are never read by any function (written "
            "only, or never used at all) cost deployment/storage gas and "
            "signal vestigial design."
        ),
        exploit_scenario=(
            "A token declares `address private admin` that is assigned in the "
            "constructor but never read; the intended admin gating silently "
            "does nothing."
        ),
        recommendation=(
            "Remove unused state variables (or document why they must "
            "remain, e.g. storage-layout compatibility in upgradeable "
            "contracts)."
        ),
    )

    def _candidates(self, contract: Contract) -> list[StateVariable]:
        """Declared variables of ``contract`` eligible for the check."""
        result: list[StateVariable] = []
        for var in contract.state_variables:
            if var.visibility == "public":
                continue  # auto-generated getter counts as a reader
            if _used_for_override_conformance(contract, var):
                continue
            result.append(var)
        return result

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts:
            read = state_variables_read_in_family(contract)
            for var in self._candidates(contract):
                if any(v is var for v in read):
                    continue
                results.append(
                    self.finding(
                        [var, " is never read in ", contract],
                        additional_fields={"visibility": var.visibility},
                    )
                )
        return results
