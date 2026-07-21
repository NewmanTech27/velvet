"""`low-level-calls` detector (spec/detectors-catalog.md §8.8 — normative).

Flags usage of low-level calls (``call``, ``delegatecall``, ``staticcall``,
``callcode``).  These do not check that the target has code and do not
propagate reverts, making them error-prone; flagged as a review aid.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import LowLevelCall


class LowLevelCalls(Detector):
    """Detect functions using low-level calls."""

    RULE = "low-level-calls"
    TITLE = "Low level calls"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#low-level-calls",
        title="Low level calls",
        description=(
            "Low-level calls (call, delegatecall, staticcall, callcode) do "
            "not check that the target has code and do not propagate "
            "reverts, making them error-prone; flagged as a review aid."
        ),
        exploit_scenario=(
            "A proxy runs `(bool ok, ) = target.call(data);` without "
            "checking the target has code; a call to an empty address "
            "silently succeeds."
        ),
        recommendation=(
            "Prefer high-level interface calls; if low-level calls are "
            "required, check the success flag and verify target code "
            "existence (extcodesize / address.code.length)."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        seen_nodes: set[int] = set()
        for function in self.compilation_unit.functions_and_modifiers:
            for node in function.nodes:
                for op in node.ir_operations:
                    if not isinstance(op, LowLevelCall):
                        continue
                    if id(node) in seen_nodes:
                        continue
                    seen_nodes.add(id(node))
                    results.append(
                        self.finding(
                            [
                                node,
                                f" is a low-level call ({op.function_name}) in ",
                                function,
                            ],
                            additional_fields={"call": op.function_name},
                        )
                    )
        return results
