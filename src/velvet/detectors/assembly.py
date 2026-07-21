"""`assembly` detector (spec/detectors-catalog.md §8.1 — normative).

Flags any use of inline assembly.  Assembly bypasses Solidity's safety
checks (type system, memory management, overflow checks), so its presence
merits manual review; it is an audit aid, not a bug per se.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.cfg_node import NodeKind
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class Assembly(Detector):
    """Detect functions that use inline assembly."""

    RULE = "assembly"
    TITLE = "Assembly usage"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#assembly",
        title="Assembly usage",
        description=(
            "Inline assembly bypasses Solidity's safety checks (type "
            "system, memory management, overflow checks). Its presence "
            "merits manual review; it is an audit aid, not a bug per se."
        ),
        exploit_scenario=(
            "A function computes `assembly { y := add(x, x) }`; reviewers "
            "must audit the block by hand because the compiler's checks no "
            "longer apply."
        ),
        recommendation=(
            "Avoid assembly unless strictly necessary; document and test "
            "each block thoroughly."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        functions = list(self.compilation_unit.functions_and_modifiers)
        for function in functions:
            if not function.contains_assembly:
                continue
            asm_node = next(
                (n for n in function.nodes if n.kind == NodeKind.ASSEMBLY), None
            )
            if asm_node is not None:
                elements: list[object] = [
                    asm_node,
                    " is an inline assembly block in ",
                    function,
                ]
            else:
                elements = [function, " uses inline assembly"]
            results.append(self.finding(elements))
        return results
