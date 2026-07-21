"""`storage-array` detector (spec/detectors-catalog.md §5.2 — normative).

``solc`` 0.4.7–0.5.9 miscompile assignments of negative literals into
signed-integer storage arrays: due to a sign-encoding bug, a stored ``-1``
can read back as a positive value.  The detector fires when the compilation
used an affected compiler and a negative value is assigned to a signed
integer array stored in storage.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Optional

from velvet.core.types import ArrayType, ElementaryType
from velvet.core.variables import Constant, StateVariable
from velvet.detectors._versions import in_version_range
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import Assignment, Unary
from velvet.ir.variables import root_base

#: Affected compiler range (spec/detectors-catalog.md §5.2).
AFFECTED_FLOOR = "0.4.7"
AFFECTED_CEILING = "0.5.9"


def _signed_integer_array(variable: Any) -> bool:
    """True when ``variable`` is a state variable of signed-int array type."""
    if not isinstance(variable, StateVariable):
        return False
    var_type = variable.type
    while isinstance(var_type, ArrayType):
        var_type = var_type.type
    return (
        isinstance(var_type, ElementaryType)
        and var_type.name.split()[0].startswith("int")
    )


def _is_negative_constant(variable: Any) -> bool:
    if not isinstance(variable, Constant):
        return False
    value = variable.value
    if isinstance(value, (int, float)):
        return value < 0
    return str(value).lstrip().startswith("-")


class StorageArray(Detector):
    """Detect negative assignments to signed storage arrays (buggy solc)."""

    RULE = "storage-array"
    TITLE = "Negative value assigned to a signed integer storage array"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#storage-array",
        title="Signed storage array miscompilation",
        description=(
            "solc 0.4.7-0.5.9 miscompile assignments of negative literals "
            "into signed-integer storage arrays: due to a sign-encoding "
            "bug, a stored -1 can read back as a positive value, corrupting "
            "any logic relying on negative sentinels."
        ),
        exploit_scenario=(
            "A contract compiled with solc 0.5.8 runs "
            "values = [int256(-1), -1, -1, -1]; the stored values read back "
            "positive and sentinel checks silently pass."
        ),
        recommendation="Compile with solc >= 0.5.10.",
    )

    def _affected_compiler(self) -> bool:
        version = self.compilation_unit.solc_version
        return in_version_range(version, AFFECTED_FLOOR, AFFECTED_CEILING)

    @staticmethod
    def _assigns_negative(rvalue: Any, function: Any) -> bool:
        """True when the value chain defining ``rvalue`` contains a negative literal."""
        defining: dict[int, Any] = {}
        for node in function.all_nodes:
            for op in node.ir_operations:
                if op.lvalue is not None:
                    defining[id(op.lvalue)] = op

        seen: set[int] = set()
        stack = [rvalue]
        while stack:
            var = stack.pop()
            if var is None or id(var) in seen:
                continue
            seen.add(id(var))
            if _is_negative_constant(var):
                return True
            origin = getattr(var, "non_ssa_version", None) or var
            op = defining.get(id(var)) or defining.get(id(origin))
            if op is None:
                continue
            if (
                isinstance(op, Unary)
                and op.operator == "-"
                and isinstance(op.rvalue, Constant)
            ):
                # unary minus applied directly to a literal => negative value
                return True
            stack.extend(op.read)
        return False

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        if not self._affected_compiler():
            return results
        seen_nodes: set[int] = set()
        for contract in self.compilation_unit.contracts:
            for function in contract.functions_and_modifiers:
                for node in function.nodes:
                    for op in node.ir_operations:
                        if not isinstance(op, Assignment):
                            continue
                        target: Optional[Any] = root_base(op.lvalue)
                        if not _signed_integer_array(target):
                            continue
                        if not self._assigns_negative(op.rvalue, function):
                            continue
                        if id(node) in seen_nodes:
                            continue
                        seen_nodes.add(id(node))
                        results.append(
                            self.finding(
                                [
                                    node,
                                    " assigns a negative value to the signed"
                                    " integer storage array ",
                                    target,
                                    " (miscompiled by solc "
                                    f"{self.compilation_unit.solc_version})",
                                ]
                            )
                        )
        return results
