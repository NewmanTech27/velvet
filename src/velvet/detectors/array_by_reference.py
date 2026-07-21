"""`array-by-reference` detector (spec/detectors-catalog.md §7.1 — normative).

Flags calls that pass a storage array to a function whose corresponding
parameter is by-value (``memory`` / unspecified location) while the callee
modifies the parameter.  The function silently operates on a *copy*; the
author usually intends the callee to mutate the caller's storage array, so
the mutation is lost.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.analyses.read_write import expand_read_variables
from velvet.core.function import FunctionLike
from velvet.core.types import ArrayType
from velvet.core.variables import LocalVariable, StateVariable
from velvet.detectors._batch_e_utils import unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import Assignment, Delete, InternalCall, Push, Unary
from velvet.ir.variables import ReferenceVariable, root_base


def _is_array_state_variable(variable: Any) -> bool:
    return isinstance(variable, StateVariable) and isinstance(variable.type, ArrayType)


#: Operations that can write *through* a reference (Index/Member only
#: create the reference; the write itself is one of these).
_WRITE_THROUGH_OPS = (Assignment, Unary, Push, Delete)


def _modifies_parameter(callee: FunctionLike, param: LocalVariable) -> bool:
    """True when ``callee`` writes ``param`` itself or through a reference.

    Indexed/member *reads* (``arr[0]`` inside an expression) only create a
    ``ReferenceVariable`` and are not writes; the actual mutations are the
    assignments/compound assignments, pushes and deletes whose lvalue is
    the parameter or a reference rooted at it.
    """
    for node in callee.all_nodes:
        for op in node.ir_operations:
            lvalue = op.lvalue
            if lvalue is None or not isinstance(op, _WRITE_THROUGH_OPS):
                continue
            if lvalue is param:
                return True
            if isinstance(lvalue, ReferenceVariable) and root_base(lvalue) is param:
                return True
    return False


def _modified_by_value_parameters(callee: FunctionLike) -> list[LocalVariable]:
    """Array-typed parameters of ``callee`` that are passed by value
    (``memory`` / unspecified location) and modified in the callee body."""
    if not isinstance(callee, FunctionLike) or not callee.is_implemented:
        return []
    result: list[LocalVariable] = []
    for param in callee.parameters:
        if param.location == "storage":
            continue  # a true storage reference: mutation propagates back
        if not isinstance(param.type, ArrayType):
            continue
        if _modifies_parameter(callee, param):
            result.append(param)
    return result


class ArrayByReference(Detector):
    """Detect storage arrays passed to by-value parameters that are modified."""

    RULE = "array-by-reference"
    TITLE = "Array passed by value to a function that modifies it"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#array-by-reference",
        title="Storage array passed to a by-value (memory) parameter",
        description=(
            "A storage array is passed to a function whose parameter is "
            "declared without the storage location, so the callee works on "
            "a copy; modifications the author expected to persist are "
            "silently lost."
        ),
        exploit_scenario=(
            "Registry.init() calls bump(slots) where bump takes "
            "uint256[2] memory arr and does arr[0] += 1; slots is never "
            "updated even though every caller assumes it is."
        ),
        recommendation=(
            "Make data locations explicit; declare the parameter storage "
            "when mutation of the caller's array is intended."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        # Cache the modified by-value parameters per callee.
        cache: dict[int, list[LocalVariable]] = {}
        for function in unique_functions(self.compilation_unit):
            for node in function.nodes:
                for op in node.ir_operations:
                    if not (isinstance(op, InternalCall) and op.function is not None):
                        continue
                    callee = op.function
                    if id(callee) not in cache:
                        cache[id(callee)] = _modified_by_value_parameters(callee)
                    modified = cache[id(callee)]
                    if not modified:
                        continue
                    for index, param in enumerate(callee.parameters):
                        if not any(p is param for p in modified):
                            continue
                        if index >= len(op.arguments):
                            continue
                        # The raw argument plus its def-chain expansion (a
                        # storage local copy resolves to its source array).
                        argument = op.arguments[index]
                        sources = [argument] + expand_read_variables(
                            [argument], function
                        )
                        if not any(_is_array_state_variable(v) for v in sources):
                            continue
                        results.append(
                            self.finding(
                                [
                                    node,
                                    " passes a storage array by value to ",
                                    callee,
                                    f"; the callee modifies parameter {param.name}"
                                    " but the mutation is lost (copy, not a"
                                    " storage reference)",
                                ]
                            )
                        )
        return results
