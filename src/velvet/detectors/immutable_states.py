"""`immutable-states` detector (spec/detectors-catalog.md §9.4 — normative).

Flags state variables that are assigned exactly once — in the constructor
(or at declaration) — and never modified afterwards.  Declaring them
``immutable`` embeds the value in the deployed bytecode, saving an SLOAD on
every read.  Variables that could be ``constant`` instead are left to
`constable-states`.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._state_family import state_variable_writers_in_family
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.detectors.constable_states import is_compile_time_evaluable


class ImmutableStates(Detector):
    """Detect constructor-set-once state variables that should be immutable."""

    RULE = "immutable-states"
    TITLE = "State variables that could be declared immutable"
    IMPACT = Impact.OPTIMIZATION
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#immutable-states",
        title="State variables that could be declared immutable",
        description=(
            "State variables assigned exactly once — in the constructor or "
            "at declaration — and never modified afterwards should be "
            "declared immutable: the value is embedded in the deployed "
            "bytecode, saving an SLOAD on every read."
        ),
        exploit_scenario=(
            "`address public owner;` is set once in the constructor and "
            "read on every privileged call; an `immutable` declaration "
            "removes those storage reads."
        ),
        recommendation="Declare constructor-set-once variables `immutable`.",
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts:
            writers = state_variable_writers_in_family(contract)
            for var in contract.state_variables:
                if var.is_constant or var.is_immutable:
                    continue
                var_writers = writers.get(id(var), (var, []))[1]
                non_constructor_writers = [
                    func for func in var_writers if not func.is_constructor
                ]
                if non_constructor_writers:
                    continue
                written_in_constructor = bool(var_writers)
                if not written_in_constructor:
                    # Only assigned at declaration: immutable only when the
                    # initializer is not compile-time evaluable (otherwise
                    # `constant` is the right keyword -> constable-states).
                    if not var.initialized:
                        continue
                    if is_compile_time_evaluable(var.expression_initial):
                        continue
                results.append(
                    self.finding(
                        [
                            var,
                            " is only assigned in the constructor and should be"
                            " declared immutable",
                        ],
                        additional_fields={"suggested_keyword": "immutable"},
                    )
                )
        return results
