"""`return-bomb` detector (spec/detectors-catalog.md §7.38 — normative).

Flags low-level calls whose returndata is copied wholesale into memory.  A
malicious callee can "return" (or revert with) an enormous payload; the
caller pays the memory-expansion cost regardless of the gas limit it set on
the sub-call, potentially running out of gas before finishing its own state
changes.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_f_utils import unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import LowLevelCall, Unpack


class ReturnBomb(Detector):
    """Detect low-level calls that copy unbounded returndata into memory."""

    RULE = "return-bomb"
    TITLE = "Low-level call copies unbounded returndata into memory"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#return-bomb",
        title="Low-level call copies unbounded returndata into memory",
        description=(
            "A low-level call's returndata is implicitly copied to memory "
            "((bool ok, bytes memory data) = target.call(...)) without "
            "bounding the copied length. A malicious callee can return an "
            "enormous payload; the caller pays the memory-expansion cost "
            "regardless of the gas limit on the sub-call."
        ),
        exploit_scenario=(
            "fetch() does (bool ok, bytes memory payload) = oracle.call(...); "
            "the oracle is attacker-controlled and returns a multi-megabyte "
            "payload, so the memory expansion burns all gas and the "
            "transaction always reverts."
        ),
        recommendation=(
            "Cap copied returndata (assembly returndatacopy with a max "
            "length, as in the ExcessivelySafeCall pattern) when calling "
            "untrusted contracts."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            unpacks = [
                op for op in function.all_ir_operations if isinstance(op, Unpack)
            ]
            for node in function.nodes:
                for op in node.ir_operations:
                    if not isinstance(op, LowLevelCall):
                        continue
                    # The call copies returndata when a tuple field beyond the
                    # success flag (index 0) is captured (e.g. the bytes data).
                    copies_returndata = any(
                        unpack.tuple_variable is op.lvalue and unpack.index >= 1
                        for unpack in unpacks
                    )
                    if not copies_returndata:
                        continue
                    results.append(
                        self.finding(
                            [
                                node,
                                " copies the returndata of a low-level ",
                                op.function_name,
                                " call into memory in ",
                                function,
                                " without bounding its length",
                            ]
                        )
                    )
        return results
