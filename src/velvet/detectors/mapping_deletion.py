"""`mapping-deletion` detector (spec/detectors-catalog.md §7.16 —
normative).

Flags ``delete`` applied to a struct that (transitively) contains a
mapping.  Per Solidity semantics, ``delete`` clears value-type members but
leaves mapping contents untouched, so the "deleted" record silently keeps
its inner mapping data and the intended cleanup does not happen.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Optional

from velvet.core.declarations import Structure
from velvet.core.types import ArrayType, MappingType, Type, UserDefinedType
from velvet.detectors._batch_e_utils import defining_ops, unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import Delete, Index, Member, Operation
from velvet.ir.variables import ReferenceVariable


def _struct_has_mapping(struct: Structure, seen: set[int]) -> bool:
    """True when ``struct`` transitively contains a mapping member."""
    if id(struct) in seen:
        return False
    seen.add(id(struct))
    for field in struct.elems:
        field_type: Optional[Type] = field.type
        while isinstance(field_type, ArrayType):
            field_type = field_type.type
        if isinstance(field_type, MappingType):
            return True
        if isinstance(field_type, UserDefinedType) and isinstance(
            field_type.type, Structure
        ):
            if _struct_has_mapping(field_type.type, seen):
                return True
    return False


def _deleted_type(
    target: Any, defs: dict[int, Operation]
) -> Optional[Type]:
    """Best-effort static type of a ``delete`` target."""
    var_type = getattr(target, "type", None)
    if var_type is not None:
        return var_type
    if isinstance(target, ReferenceVariable):
        op = defs.get(id(target))
        if isinstance(op, Index):
            base_type = _deleted_type(op.base, defs)
            if isinstance(base_type, MappingType):
                return base_type.type_to
            if isinstance(base_type, ArrayType):
                return base_type.type
        elif isinstance(op, Member):
            base_type = _deleted_type(op.base, defs)
            if isinstance(base_type, UserDefinedType) and isinstance(
                base_type.type, Structure
            ):
                for field in base_type.type.elems:
                    if field.name == op.member_name:
                        return field.type
    return None


class MappingDeletion(Detector):
    """Detect ``delete`` on structs that contain a mapping."""

    RULE = "mapping-deletion"
    TITLE = "Deletion on a struct containing a mapping"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#mapping-deletion",
        title="Mapping deletion leaves inner data behind",
        description=(
            "delete applied to a struct (or a mapping value) that contains "
            "a mapping clears the value-type members but leaves the inner "
            "mapping untouched; the record's mapping data survives the "
            "deletion."
        ),
        exploit_scenario=(
            "Profiles.leave() runs delete profiles[msg.sender]; the "
            "profile's friends mapping keeps all its entries, so storage "
            "refunds are smaller than expected and stale permissions "
            "linger."
        ),
        recommendation=(
            "Use a boolean active flag to disable records, or track keys "
            "separately and delete mapping entries explicitly."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            defs = defining_ops(function)
            for node in function.nodes:
                for op in node.ir_operations:
                    if not isinstance(op, Delete):
                        continue
                    target_type = _deleted_type(op.target, defs)
                    while isinstance(target_type, ArrayType):
                        target_type = target_type.type
                    if not (
                        isinstance(target_type, UserDefinedType)
                        and isinstance(target_type.type, Structure)
                    ):
                        continue
                    struct = target_type.type
                    if not _struct_has_mapping(struct, set()):
                        continue
                    results.append(
                        self.finding(
                            [
                                node,
                                " deletes a record of struct ",
                                struct,
                                " which contains a mapping; the inner "
                                "mapping data survives the deletion in ",
                                function,
                            ]
                        )
                    )
        return results
