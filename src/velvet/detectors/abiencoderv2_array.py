"""`abiencoderv2-array` detector (spec/detectors-catalog.md §5.1 — normative).

``solc`` 0.4.7–0.5.9 contain a bug in the ABI encoder v2: when a
multi-dimensional array is passed to ``abi.encode``, elements are encoded
with an off-by-one shift, silently producing wrong byte data.  The detector
fires when the compilation used an affected compiler and a storage array of
arrays is passed to ``abi.encode``.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.analyses.read_write import expand_read_variables
from velvet.core.types import ArrayType
from velvet.core.variables import StateVariable
from velvet.detectors._versions import in_version_range
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import SolidityCall

#: Affected compiler range (spec/detectors-catalog.md §5.1).
AFFECTED_FLOOR = "0.4.7"
AFFECTED_CEILING = "0.5.9"


def _is_nested_array(variable: Any) -> bool:
    """True when ``variable`` is a state variable of array-of-arrays type."""
    if not isinstance(variable, StateVariable):
        return False
    var_type = variable.type
    return isinstance(var_type, ArrayType) and isinstance(var_type.type, ArrayType)


class AbiEncoderV2Array(Detector):
    """Detect abi.encode of nested storage arrays with affected solc."""

    RULE = "abiencoderv2-array"
    TITLE = "abi.encode on a multi-dimensional storage array (buggy encoder)"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#abiencoderv2-array",
        title="Abi.encode of a nested array with a buggy compiler",
        description=(
            "solc 0.4.7-0.5.9 contain a bug in the ABI encoder v2: when a "
            "multi-dimensional array is passed to abi.encode, elements are "
            "encoded with an off-by-one shift, silently producing wrong "
            "byte data."
        ),
        exploit_scenario=(
            "A contract compiled with solc 0.5.8 returns "
            "abi.encode(matrix); the encoded bytes are shifted and every "
            "consumer decodes corrupted values."
        ),
        recommendation="Compile with solc >= 0.5.10.",
    )

    def _affected_compiler(self) -> bool:
        version = self.compilation_unit.solc_version
        return in_version_range(version, AFFECTED_FLOOR, AFFECTED_CEILING)

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        if not self._affected_compiler():
            return results
        seen_nodes: set[int] = set()
        for contract in self.compilation_unit.contracts:
            for function in contract.functions_and_modifiers:
                for node in function.nodes:
                    for op in node.ir_operations:
                        if not (
                            isinstance(op, SolidityCall)
                            and op.function.name == "abi.encode"
                        ):
                            continue
                        if id(node) in seen_nodes:
                            continue
                        sources = expand_read_variables(op.arguments, function)
                        if any(_is_nested_array(var) for var in sources):
                            seen_nodes.add(id(node))
                            results.append(
                                self.finding(
                                    [
                                        node,
                                        " passes a multi-dimensional storage array"
                                        " to abi.encode in ",
                                        function,
                                        " (buggy encoder in solc "
                                        f"{self.compilation_unit.solc_version})",
                                    ]
                                )
                            )
        return results
