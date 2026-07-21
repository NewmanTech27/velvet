"""`shadowing-local` detector (spec/detectors-catalog.md §7.32 — normative).

A local declaration (parameter, named return, or variable) has the same
name as a state variable, function, event, or an outer local visible in the
same scope.  References inside the scope then resolve to the local while
readers (and later maintainers) assume the contract-level declaration —
writes update the wrong entity.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.variables import LocalVariable
from velvet.detectors._batch_d_utils import function_local_declarations
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


def _declared_locals(function) -> list[LocalVariable]:
    """Parameters, returns and body locals (synthesized temps excluded)."""
    body_locals, seeded = function_local_declarations(function)
    synthesized = {id(v) for v in function.synthesized_locals}
    result: list[LocalVariable] = []
    seen: set[int] = set()
    for var in body_locals + [v for v in seeded if id(v) not in synthesized]:
        if id(var) in seen:
            continue
        seen.add(id(var))
        result.append(var)
    return result


class ShadowingLocal(Detector):
    """Detect local declarations shadowing contract-level names."""

    RULE = "shadowing-local"
    TITLE = "Local variable shadows a state variable, function or event"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#shadowing-local",
        title="Local variable shadows a state variable, function or event",
        description=(
            "A local declaration reuses the name of a state variable, "
            "function, event, or an outer local. Uses inside the scope bind "
            "to the local, so reads and writes that appear to target the "
            "contract-level declaration silently operate on the shadow."
        ),
        exploit_scenario=(
            "report(uint256 total) shadows the state variable total; the "
            "function body updates the parameter while the storage total is "
            "left unchanged."
        ),
        recommendation=(
            "Rename the local declaration so it differs from every visible "
            "state variable, function and event."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts:
            state_names = {v.name for v in contract.state_variables_ordered}
            function_names = {
                f.name
                for f in contract.available_functions_from_inheritances()
                if f.name and f.name != "constructor"
            }
            event_names = {
                e.name for member in [contract, *contract.inheritance] for e in member.events
            }
            for function in contract.functions_and_modifiers:
                locals_ = [v for v in _declared_locals(function) if v.name]
                by_name: dict[str, list[LocalVariable]] = {}
                for var in locals_:
                    by_name.setdefault(var.name, []).append(var)
                for var in locals_:
                    shadowed: list[str] = []
                    if var.name in state_names:
                        shadowed.append("state variable")
                    if var.name in function_names:
                        shadowed.append("function")
                    if var.name in event_names:
                        shadowed.append("event")
                    if len(by_name[var.name]) > 1:
                        shadowed.append("outer local")
                    if not shadowed:
                        continue
                    # For same-name locals report only the later declarations.
                    if shadowed == ["outer local"] and by_name[var.name][0] is var:
                        continue
                    results.append(
                        self.finding(
                            [
                                var,
                                " shadows a ",
                                "/".join(shadowed),
                                " named ",
                                var.name,
                                " in ",
                                function,
                            ]
                        )
                    )
        return results
