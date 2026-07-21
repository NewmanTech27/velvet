"""`uninitialized-state` detector (spec/detectors-catalog.md §7.7 —
normative).

Flags state variables that are never initialized anywhere in the codebase —
no inline initializer and no assignment in any function (constructor
included) of the declaring contract or its descendants — while being read.
Such variables keep their zero value; reads of them are usually bugs (the
author assumed they were set).

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._state_family import (
    state_variable_writers_in_family,
    state_variables_read_in_family,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class UninitializedState(Detector):
    """Detect state variables that are read but never written anywhere."""

    RULE = "uninitialized-state"
    TITLE = "Uninitialized state variable"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#uninitialized-state",
        title="Uninitialized state variable",
        description=(
            "A state variable is read but never assigned anywhere in the "
            "codebase (no inline initializer, no constructor or setter "
            "write), so it keeps its zero value; logic depending on it is "
            "silently broken."
        ),
        exploit_scenario=(
            "Bank reads lockTime in withdraw() but no function ever "
            "assigns it, so the timelock check always passes at time 0."
        ),
        recommendation=(
            "Initialize the variable (inline or in the constructor) or add "
            "the intended setter; remove it if unused."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts:
            if contract.is_interface:
                continue
            writers = state_variable_writers_in_family(contract)
            read_vars = state_variables_read_in_family(contract)
            for var in contract.state_variables:
                if var.is_constant or var.is_immutable:
                    continue
                if var.initialized:
                    continue
                if id(var) in writers:
                    continue  # assigned somewhere in the family
                if not any(v is var for v in read_vars):
                    continue  # never read: unused-state's territory
                results.append(
                    self.finding(
                        [
                            var,
                            " is never initialized anywhere in the codebase "
                            "but is read in ",
                            contract,
                        ]
                    )
                )
        return results
