"""`uninitialized-local` detector (spec/detectors-catalog.md §7.6 —
normative).

Flags reads of local variables that are not definitely assigned on every
path leading to the read.  An uninitialized local holds whatever data was
already at its stack/memory location, so the read returns unpredictable
values; when the variable is a storage pointer the write goes to arbitrary
storage slots.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_d_utils import (
    DefiniteAssignment,
    uses_before_assignment,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class UninitializedLocal(Detector):
    """Detect reads of uninitialized local variables."""

    RULE = "uninitialized-local"
    TITLE = "Uninitialized local variable read"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#uninitialized-local",
        title="Uninitialized local variable",
        description=(
            "A local variable is read before it is assigned on every path. "
            "Uninitialized locals hold whatever data was at their "
            "stack/memory location; for storage pointers a write through "
            "them overwrites arbitrary storage slots."
        ),
        exploit_scenario=(
            "pick(bool up, uint256 a, uint256 b) declares uint256 val "
            "uninitialized and returns val when up is false: the caller "
            "receives stack garbage instead of a value."
        ),
        recommendation=(
            "Initialize every local at declaration, or ensure all paths "
            "assign it before any use."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        reported: set[tuple[int, int]] = set()
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.available_functions_from_inheritances():
                if not function.is_implemented:
                    continue
                analysis = DefiniteAssignment(function)
                if not analysis.body_locals:
                    continue
                for var, node, _idx, _op in uses_before_assignment(function, analysis):
                    key = (id(var), id(node))
                    if key in reported:
                        continue
                    reported.add(key)
                    results.append(
                        self.finding(
                            [
                                node,
                                " reads ",
                                var,
                                " before it is assigned on every path in ",
                                function,
                            ]
                        )
                    )
        return results
