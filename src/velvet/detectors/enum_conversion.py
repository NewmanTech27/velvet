"""`enum-conversion` detector (spec/detectors-catalog.md §5.4 — normative).

``solc`` < 0.4.5 performs no range check when converting an integer to an
enum type, so out-of-range inputs produce undefined enum values and
unexpected downstream behavior.  The detector fires when the compilation
used an affected compiler and an explicit integer-to-enum conversion
(``EnumType(x)``) is reachable with user-controlled input.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.analyses.read_write import expand_read_variables
from velvet.core.declarations import Enum
from velvet.core.types import UserDefinedType
from velvet.core.variables import LocalVariable
from velvet.detectors._batch_g_utils import compiled_before
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import TypeConversion

#: Range checks on enum conversions were introduced in solc 0.4.5.
FIXED_VERSION = "0.4.5"


def _is_enum_conversion(op: Any) -> bool:
    """True for a TypeConversion whose target type is an enum."""
    if not isinstance(op, TypeConversion):
        return False
    target = op.type
    return isinstance(target, UserDefinedType) and isinstance(target.type, Enum)


class EnumConversion(Detector):
    """Detect out-of-range enum conversions with affected solc."""

    RULE = "enum-conversion"
    TITLE = "Integer-to-enum conversion without range check (buggy compiler)"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#enum-conversion",
        title="Out-of-range enum conversion with a buggy compiler",
        description=(
            "solc < 0.4.5 performs no range check when converting an "
            "integer to an enum type; out-of-range inputs produce "
            "undefined enum values."
        ),
        exploit_scenario=(
            "Machine.set(uint256 s) returns State(s) under solc 0.4.2; "
            "calling set(7) materializes the nonexistent State 7 and the "
            "downstream switch falls through every branch."
        ),
        recommendation=(
            "Use a modern compiler; if stuck on old solc, manually "
            "range-check the input before the conversion."
        ),
    )

    @staticmethod
    def _user_controlled(function: Any, op: TypeConversion) -> bool:
        """True when the converted value derives from a function parameter."""
        sources = expand_read_variables(op.read, function)
        return any(
            isinstance(var, LocalVariable)
            and any(var is param for param in function.parameters)
            for var in sources
        )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        if not compiled_before(self.compilation_unit, FIXED_VERSION):
            return results
        for contract in self.compilation_unit.contracts:
            for function in contract.functions_and_modifiers:
                for node in function.nodes:
                    for op in node.ir_operations:
                        if not _is_enum_conversion(op):
                            continue
                        if not self._user_controlled(function, op):
                            continue
                        results.append(
                            self.finding(
                                [
                                    node,
                                    f" converts user-controlled input to enum {op.type}"
                                    " without a range check in ",
                                    function,
                                    " (buggy conversion in solc "
                                    f"{self.compilation_unit.solc_version})",
                                ]
                            )
                        )
        return results
