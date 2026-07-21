"""`unused-return` detector (spec/detectors-catalog.md §7.28 — normative).

Flags calls to value-returning, non-mutating (``pure``/``view``) functions
whose result is silently discarded — e.g. ``a.add(b)`` via a math library
without assigning the result, so the "computation" is a no-op.  A discarded
result surfaces in the IR as a call whose lvalue temporary is never read.

Calls to state-mutating functions are out of scope (their effect is the
point); so are low-level calls, whose dropped success flag is the job of
`unchecked-lowlevel`.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_e_utils import unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import HighLevelCall, InternalCall


class UnusedReturn(Detector):
    """Detect discarded return values of pure/view-like calls."""

    RULE = "unused-return"
    TITLE = "Return value of a pure/view call is discarded"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#unused-return",
        title="Unused return value",
        description=(
            "The return value of a pure/view-like call is discarded even "
            "though the result was the whole point of the call (e.g. "
            "library math); the computation is a silent no-op."
        ),
        exploit_scenario=(
            "run() executes v.twice() via a math library but never assigns "
            "the result; v is returned unchanged, miscomputing every "
            "downstream figure."
        ),
        recommendation=(
            "Assign and use the return value, or remove the dead call."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            # ids of every variable read anywhere in the function
            read_ids: set[int] = set()
            for node in function.all_nodes:
                for op in node.ir_operations:
                    for var in op.read:
                        read_ids.add(id(var))
            for node in function.nodes:
                for op in node.ir_operations:
                    if not isinstance(op, (HighLevelCall, InternalCall)):
                        continue
                    callee = op.function
                    if callee is None or not callee.returns:
                        continue
                    if not (callee.pure or callee.view):
                        continue
                    if op.lvalue is None or id(op.lvalue) in read_ids:
                        continue
                    results.append(
                        self.finding(
                            [
                                node,
                                " discards the return value of ",
                                callee,
                                " in ",
                                function,
                                "; the computation has no effect",
                            ]
                        )
                    )
        return results
