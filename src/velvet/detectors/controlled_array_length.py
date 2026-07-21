"""`controlled-array-length` detector (spec/detectors-catalog.md §7.8 —
normative).

On compiler versions that allow direct ``array.length`` assignment
(solc < 0.6.0), flag assignments where the new length is tainted by user
input (function parameter or user-controlled state).  Setting the length of
a storage array to an arbitrary value overlaps its data slots with other
storage variables, enabling arbitrary storage writes.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from packaging.version import Version

from velvet.analyses.dependency import is_tainted
from velvet.analyses.read_write import expand_read_variables
from velvet.core.types import ArrayType, ElementaryType
from velvet.core.variables import StateVariable
from velvet.detectors._batch_b_utils import is_user_settable
from velvet.detectors._versions import parse_solc_version
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import Assignment, Index, Member
from velvet.ir.variables import ReferenceVariable, root_base

#: solc 0.6.0 removed direct array.length assignment (catalog §7.8).
FIXED_VERSION = Version("0.6.0")


def _length_member_ref(
    op: Assignment, function: Any
) -> tuple[ReferenceVariable, Any] | None:
    """The (.length, array-base) pair when ``op`` assigns ``<base>.length``.

    The reference-producing op (a ``Member``/``Index`` whose lvalue is the
    same REF) gives the member name; a plain ``id(lvalue)`` map cannot be
    used because the write-through ``Assignment`` shares the REF lvalue.
    """
    ref = op.lvalue
    if not isinstance(ref, ReferenceVariable):
        return None
    for node in function.all_nodes:
        for producer in node.ir_operations:
            if producer.lvalue is not ref:
                continue
            if isinstance(producer, Member) and producer.member_name == "length":
                return ref, producer.base
            if isinstance(producer, (Member, Index)):
                return None
    return None


def _resizable_container(var_type: Any) -> bool:
    """Storage containers whose length pre-0.6 solc lets users assign."""
    if isinstance(var_type, ArrayType) and var_type.is_dynamic:
        return True
    return isinstance(var_type, ElementaryType) and var_type.name == "bytes"


class ControlledArrayLength(Detector):
    """Detect user-controlled assignments to storage array length."""

    RULE = "controlled-array-length"
    TITLE = "Array length assigned from user-controlled value"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#controlled-array-length",
        title="Array length assigned from user-controlled value",
        description=(
            "On solc versions that allow direct array.length assignment, "
            "setting the length of a storage array from user-controlled "
            "input corrupts storage layout: array data slots overlap other "
            "state variables, giving arbitrary storage writes."
        ),
        exploit_scenario=(
            "Pool.resize(n) executes entries.length = n with n supplied by "
            "the caller; the attacker sets a huge length so entries[i] "
            "aliases the owner slot and overwrites it."
        ),
        recommendation=(
            "Never assign array.length from user input; use push/pop "
            "(solc >= 0.6.0 removes length assignment entirely)."
        ),
    )

    def _affected_compiler(self) -> bool:
        version = parse_solc_version(self.compilation_unit.solc_version)
        return version is not None and version < FIXED_VERSION

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        if not self._affected_compiler():
            return results
        seen_functions: set[int] = set()
        for contract in self.compilation_unit.contracts_derived:
            functions = list(contract.available_functions_from_inheritances())
            functions += list(contract.all_modifiers())
            for function in functions:
                if id(function) in seen_functions:
                    continue
                seen_functions.add(id(function))
                if function.is_protected:
                    continue
                for node in function.all_nodes:
                    for op in node.ir_operations:
                        if not isinstance(op, Assignment):
                            continue
                        pair = _length_member_ref(op, function)
                        if pair is None:
                            continue
                        ref, base = pair
                        storage_root = root_base(ref)
                        if not isinstance(storage_root, StateVariable):
                            continue
                        if not _resizable_container(getattr(base, "type", None)):
                            continue
                        rvalue = op.rvalue
                        sources = expand_read_variables([rvalue], function)
                        controlled = is_tainted(rvalue, function) or any(
                            isinstance(var, StateVariable)
                            and is_user_settable(var, contract)
                            for var in sources
                        )
                        if not controlled:
                            continue
                        results.append(
                            self.finding(
                                [
                                    node,
                                    " assigns a user-controlled length to "
                                    "the storage array ",
                                    storage_root,
                                    " in ",
                                    function,
                                ]
                            )
                        )
        return results
