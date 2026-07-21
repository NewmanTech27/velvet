"""`uninitialized-fptr-cst` detector (spec/detectors-catalog.md §5.5 —
normative).

solc 0.4.5–0.4.26 and 0.5.0–0.5.8 accept calls through function-pointer
variables declared but never assigned inside a constructor: the jump target
is zero and the deployment reverts (or, on those compilers, behaves
unexpectedly).  The detector fires when an affected compiler was used and a
constructor calls an internal function pointer that is not definitely
assigned before the call.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.variables import LocalVariable
from velvet.detectors._batch_d_utils import DefiniteAssignment
from velvet.detectors._versions import in_version_range
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import InternalDynamicCall
from velvet.ir.variables import root_base

#: Affected compiler ranges (spec/detectors-catalog.md §5.5).
AFFECTED_RANGES = (("0.4.5", "0.4.26"), ("0.5.0", "0.5.8"))


class UninitializedFunctionPointerConstructor(Detector):
    """Detect calls to unassigned function pointers in constructors."""

    RULE = "uninitialized-fptr-cst"
    TITLE = "Uninitialized function pointer call in a constructor"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#uninitialized-fptr-cst",
        title="Uninitialized function pointer call in a constructor",
        description=(
            "solc 0.4.5-0.4.26 and 0.5.0-0.5.8 accept constructor code that "
            "calls an internal function pointer variable that was never "
            "assigned; the call jumps to an invalid target and the "
            "deployment reverts."
        ),
        exploit_scenario=(
            "constructor() { function(uint256) internal returns (uint256) cb;"
            " cb(1); } compiles with solc 0.5.8 but the deployment always "
            "reverts at the uninitialized call."
        ),
        recommendation=(
            "Assign the function pointer before calling it, or compile with "
            "solc >= 0.5.9 which rejects the code."
        ),
    )

    def _affected_compiler(self) -> bool:
        version = self.compilation_unit.solc_version
        return any(
            in_version_range(version, floor, ceiling)
            for floor, ceiling in AFFECTED_RANGES
        )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        if not self._affected_compiler():
            return results
        for contract in self.compilation_unit.contracts:
            for function in contract.functions:
                if not function.is_constructor:
                    continue
                analysis = DefiniteAssignment(function)
                for node in function.nodes:
                    if not node.is_reachable:
                        continue
                    for op_index, op in enumerate(node.ir_operations):
                        if not isinstance(op, InternalDynamicCall):
                            continue
                        base = root_base(op.function_variable)
                        if not isinstance(base, LocalVariable):
                            continue
                        if base in analysis.assigned_before(node, op_index):
                            continue
                        results.append(
                            self.finding(
                                [
                                    node,
                                    " calls the uninitialized function "
                                    "pointer ",
                                    base,
                                    " in the constructor of ",
                                    contract,
                                ]
                            )
                        )
        return results
