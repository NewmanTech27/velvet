"""`write-after-write` detector (spec/detectors-catalog.md §7.20 —
normative).

Flags variables assigned twice with no intervening read, making the first
write dead — frequently the residue of an incomplete refactor.

The analysis runs on the SSA view: every assignment produces a fresh
version of the variable, so a version that is (a) defined by a real write
(not a phi merge), (b) never read anywhere in the function, and
(c) superseded by a later version of the same variable is precisely a
write overwritten without any read.  The one accepted idiom is a
declaration default (``uint256 x = 0;``) later overwritten.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.core.cfg_node import CFGNode, NodeKind
from velvet.core.function import FunctionLike
from velvet.core.variables import Constant, LocalVariable, StateVariable
from velvet.detectors._batch_e_utils import is_ir_temp, unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import Assignment, Operation, Phi
from velvet.ir.ssa import non_ssa_version_of


def _dead_writes(function: FunctionLike) -> list[tuple[CFGNode, Any, Operation]]:
    """(node, origin variable, op) of writes overwritten without a read."""
    defs: list[tuple[CFGNode, Operation, Any]] = []  # per SSA version
    read_ids: set[int] = set()
    for node in function.nodes:
        for op in node.ir_operations_ssa:
            for var in op.read:
                read_ids.add(id(var))
            if op.lvalue is not None:
                defs.append((node, op, op.lvalue))

    # Latest SSA index per origin variable.
    latest: dict[int, int] = {}
    for _node, _op, version in defs:
        origin = non_ssa_version_of(version)
        index = getattr(version, "_ssa_index", 0)
        key = id(origin)
        if index > latest.get(key, -1):
            latest[key] = index

    dead: list[tuple[CFGNode, Any, Operation]] = []
    for node, op, version in defs:
        if isinstance(op, Phi):
            continue
        if id(version) in read_ids:
            continue
        origin = non_ssa_version_of(version)
        if is_ir_temp(origin) or not isinstance(origin, (LocalVariable, StateVariable)):
            continue
        index = getattr(version, "_ssa_index", 0)
        if index >= latest.get(id(origin), 0):
            continue  # final version: live out of the function
        if (
            isinstance(op, Assignment)
            and isinstance(op.rvalue, Constant)
            and node.kind == NodeKind.VARIABLE
        ):
            continue  # declaration default later overwritten — idiom
        dead.append((node, origin, op))
    return dead


class WriteAfterWrite(Detector):
    """Detect writes overwritten without an intervening read."""

    RULE = "write-after-write"
    TITLE = "Variable written twice without an intervening read"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#write-after-write",
        title="Write after write",
        description=(
            "A local/state variable is written and then written again on a "
            "path with no read of the variable between the two writes; the "
            "first write is dead — frequently the residue of an incomplete "
            "refactor."
        ),
        exploit_scenario=(
            "quote() sets fee = 100 and then unconditionally overwrites it "
            "with fee = partner ? 80 : 100; the default-fee branch the "
            "author intended is gone."
        ),
        recommendation=(
            "Remove the dead write or restructure so intermediate values "
            "are actually used."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            reported: set[int] = set()
            for node, origin, _op in _dead_writes(function):
                key = (id(node), id(origin))
                if key in reported:
                    continue
                reported.add(key)
                results.append(
                    self.finding(
                        [
                            node,
                            " writes ",
                            origin,
                            " but the value is overwritten without being "
                            "read in ",
                            function,
                        ]
                    )
                )
        return results
