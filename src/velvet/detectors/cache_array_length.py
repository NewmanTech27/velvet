"""`cache-array-length` detector (spec/detectors-catalog.md §9.2 — normative).

Flags ``for`` loops whose condition re-reads a *storage* array's ``.length``
on every iteration while the loop never changes that length.  Each
evaluation is an extra ``SLOAD``; caching the length in a local saves gas per
iteration.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.cfg_node import NodeKind
from velvet.core.variables import StateVariable
from velvet.detectors._batch_f_utils import unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import Delete, Member, Push


class CacheArrayLength(Detector):
    """Detect storage-array lengths re-read in loop conditions."""

    RULE = "cache-array-length"
    TITLE = "Storage array length should be cached before the loop"
    IMPACT = Impact.OPTIMIZATION
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#cache-array-length",
        title="Storage array length should be cached before the loop",
        description=(
            "A for loop's condition re-reads a storage array's .length on "
            "every iteration while the loop never changes that length. Each "
            "evaluation is an extra SLOAD; caching the length in a local "
            "saves gas per iteration."
        ),
        exploit_scenario=(
            "sum() loops for (i = 0; i < ids.length; i++); over a 10k-element "
            "array the repeated SLOADs waste thousands of gas per call."
        ),
        recommendation=(
            "Cache the length before the loop (uint256 n = ids.length; for "
            "(uint256 i = 0; i < n; i++) ...)."
        ),
    )

    @staticmethod
    def _length_member_bases(function) -> list[tuple[object, StateVariable]]:
        """``(node, state_array)`` for each loop condition reading ``array.length``."""
        hits: list[tuple[object, StateVariable]] = []
        for node in function.nodes:
            if node.kind != NodeKind.IF_LOOP:
                continue
            for op in node.ir_operations:
                if (
                    isinstance(op, Member)
                    and op.member_name == "length"
                    and isinstance(op.base, StateVariable)
                ):
                    hits.append((node, op.base))
        return hits

    @staticmethod
    def _length_mutated_in_loop(function, array: StateVariable) -> bool:
        """True when the loop body pushes/pops/deletes ``array``."""
        for node in function.nodes:
            if not node.is_inside_loop:
                continue
            for op in node.ir_operations:
                if isinstance(op, Push) and op.array is array:
                    return True
                if isinstance(op, Delete) and op.target is array:
                    return True
        return False

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        reported: set[int] = set()
        for function in unique_functions(self.compilation_unit):
            for node, array in self._length_member_bases(function):
                if id(node) in reported:
                    continue
                if self._length_mutated_in_loop(function, array):
                    continue
                reported.add(id(node))
                results.append(
                    self.finding(
                        [
                            node,
                            " re-reads the storage array ",
                            array,
                            ".length on every loop iteration in ",
                            function,
                            "; cache it in a local before the loop",
                        ]
                    )
                )
        return results
