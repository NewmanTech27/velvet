"""`uninitialized-storage` detector (spec/detectors-catalog.md §7.7 —
normative).

A local storage pointer (e.g. ``MyStruct s;`` inside a function) is read or
written before being assigned to a storage location, so it aliases storage
slot 0 and corrupts the contract's state.  Only pre-0.5 compilers accept
such code (the catalog notes it is reachable there only); modern solc
rejects uninitialized storage pointers, so the detector fires whenever the
pattern appears without an additional version gate.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_d_utils import (
    DefiniteAssignment,
    is_storage_pointer_candidate,
    uses_before_assignment,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class UninitializedStorage(Detector):
    """Detect local storage pointers used before being assigned."""

    RULE = "uninitialized-storage"
    TITLE = "Uninitialized storage pointer"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#uninitialized-storage",
        title="Uninitialized storage pointer",
        description=(
            "A local variable of struct/array type with storage location is "
            "read or written before being bound to a storage location. The "
            "uninitialized pointer aliases storage slot 0, silently "
            "overwriting the contract's first state variables (pre-0.5 "
            "compilers accept this code)."
        ),
        exploit_scenario=(
            "function corrupt() { Entry e; e.amount = 0; } writes through "
            "the uninitialized storage pointer e and zeroes the owner field "
            "stored at slot 0."
        ),
        recommendation=(
            "Bind the pointer when declaring it (Entry storage e = "
            "entries[0];) or use a memory variable."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts:
            for function in contract.functions_and_modifiers:
                if not function.is_implemented:
                    continue
                analysis = DefiniteAssignment(function)
                candidates = {
                    id(var)
                    for var in analysis.body_locals
                    if is_storage_pointer_candidate(var)
                }
                if not candidates:
                    continue
                reported: set[int] = set()
                for var, node, _idx, _op in uses_before_assignment(
                    function, analysis, candidates
                ):
                    if id(var) in reported:
                        continue
                    reported.add(id(var))
                    results.append(
                        self.finding(
                            [
                                node,
                                " uses the uninitialized storage pointer ",
                                var,
                                " before it is assigned to a storage location in ",
                                function,
                            ]
                        )
                    )
        return results
