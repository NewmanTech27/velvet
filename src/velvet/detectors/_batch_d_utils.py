"""Shared helpers for batch D detectors.

The main piece is a forward *definite-assignment* (must-analysis) dataflow
over a function's own CFG, used by the ``uninitialized-*`` family to find
locals read before they are assigned.  Small classification helpers for
types and locals live here too.  Original clean-room implementation.
"""

from __future__ import annotations

import re
from typing import Iterator, Optional

from velvet.core.cfg_node import CFGNode, NodeKind
from velvet.core.declarations import Structure
from velvet.core.function import FunctionLike
from velvet.core.types import (
    ArrayType,
    ElementaryType,
    MappingType,
    TupleType,
    Type,
    UserDefinedType,
)
from velvet.core.variables import LocalVariable, Variable
from velvet.ir.operations import Operation
from velvet.ir.variables import ReferenceVariable, root_base


# --------------------------------------------------------------------- locals


def function_local_declarations(
    function: FunctionLike,
) -> tuple[list[LocalVariable], list[LocalVariable]]:
    """Split a function's locals into (body-declared, entry-assigned).

    Entry-assigned ("seeded") locals are parameters, named returns,
    synthesized temporaries, and variables the parser already marked
    initialized without a body declaration node (e.g. try/catch clause
    parameters).  Everything else is a body local whose assignment must be
    established by the CFG.
    """
    declared_via_node: set[int] = set()
    for node in function.nodes:
        var = node.variable_declaration
        if var is not None:
            declared_via_node.add(id(var))

    appearing: dict[int, LocalVariable] = {}
    for node in function.nodes:
        for op in node.ir_operations:
            for var in op.used:
                base = root_base(var)
                if isinstance(base, LocalVariable):
                    appearing[id(base)] = base

    seeded: list[LocalVariable] = []
    seeded += list(function.parameters)
    seeded += list(function.returns)
    seeded += list(function.synthesized_locals)

    body_locals: list[LocalVariable] = []
    skip = {id(v) for v in seeded}
    for var in appearing.values():
        if id(var) in skip:
            continue
        if id(var) in declared_via_node:
            body_locals.append(var)
        elif var.initialized:
            # try/catch clause parameters and similar: assigned implicitly.
            seeded.append(var)
            skip.add(id(var))
        else:
            body_locals.append(var)
    return body_locals, seeded


def _directly_used_locals(op: Operation) -> list[LocalVariable]:
    """Locals whose value the operation needs (reads + write-through-refs).

    Writing ``e.amount = 0`` reads the base ``e`` (via the ``Member`` op),
    so both read slots and reference-lvalue roots count as uses.
    """
    result: list[LocalVariable] = []
    seen: set[int] = set()

    def _add(var: Variable) -> None:
        base = root_base(var)
        if isinstance(base, LocalVariable) and id(base) not in seen:
            seen.add(id(base))
            result.append(base)

    for var in op.read:
        _add(var)
    lvalue = getattr(op, "lvalue", None)
    if isinstance(lvalue, ReferenceVariable):
        _add(lvalue)
    return result


def _assigned_local(op: Operation) -> Optional[LocalVariable]:
    lvalue = getattr(op, "lvalue", None)
    if isinstance(lvalue, LocalVariable):
        return lvalue
    return None


#: Yul assignment target (``x := ...``) inside an opaque assembly block.
_ASM_TARGET_RE = re.compile(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*:=")
#: Yul ``let`` declarations are block-local and must not count as assigning
#: a Solidity local of the same name.
_ASM_LET_RE = re.compile(
    r"\blet\s+([A-Za-z_$][A-Za-z0-9_$]*(?:\s*,\s*[A-Za-z_$][A-Za-z0-9_$]*)*)\s*:="
)


def _assembly_assigned_names(node: CFGNode) -> set[str]:
    """Identifiers assigned inside an opaque inline-assembly node.

    Inline assembly is modeled as a single opaque ``ASSEMBLY`` node with no
    IR, so writes like ``ptr := add(buffer, 0x20)`` are invisible to the
    dataflow; without this, every local written only from assembly reads as
    uninitialized.  Names are recovered from the node's source slice.
    """
    content = node.source_mapping.content
    if not content:
        return set()
    names = set(_ASM_TARGET_RE.findall(content))
    for group in _ASM_LET_RE.findall(content):
        for name in group.split(","):
            names.discard(name.strip())
    return names


def _node_assigned_locals(node: CFGNode) -> Iterator[LocalVariable]:
    """Locals whose assignment completes within ``node`` (IR-level)."""
    for op in node.ir_operations:
        var = _assigned_local(op)
        if var is not None:
            yield var
    # A declaration with an initializer (or a for-header declaration, which
    # the parser marks initialized) establishes the variable's value even
    # when the declaration node carries no assignment op.
    decl = node.variable_declaration
    if isinstance(decl, LocalVariable) and decl.initialized:
        yield decl


# ------------------------------------------------------- definite assignment


class DefiniteAssignment:
    """Must-assignment facts for one function body.

    ``in_sets[id(node)]`` holds the locals assigned on every path reaching
    ``node``.  Only reachable nodes are analyzed; unreachable ones keep the
    universe set so no finding is produced for dead code.
    """

    def __init__(self, function: FunctionLike) -> None:
        self.body_locals, self.seeded = function_local_declarations(function)
        self._universe: set[LocalVariable] = set(self.body_locals) | set(self.seeded)
        self._by_name: dict[str, LocalVariable] = {v.name: v for v in self._universe}
        self._asm_assigned: dict[int, set[LocalVariable]] = {}
        for node in function.nodes:
            if node.kind is NodeKind.ASSEMBLY:
                names = _assembly_assigned_names(node)
                assigned = {self._by_name[n] for n in names if n in self._by_name}
                if assigned:
                    self._asm_assigned[id(node)] = assigned
        self.in_sets: dict[int, set[LocalVariable]] = {}
        self._analyze(function)

    def _node_assignments(self, node: CFGNode) -> Iterator[LocalVariable]:
        yield from _node_assigned_locals(node)
        yield from self._asm_assigned.get(id(node), ())

    def _analyze(self, function: FunctionLike) -> None:
        nodes = [n for n in function.nodes if n.is_reachable]
        entry = function.entry_point
        seed = set(self.seeded)
        in_sets: dict[int, set[LocalVariable]] = {}
        out_sets: dict[int, set[LocalVariable]] = {}
        for node in nodes:
            in_sets[id(node)] = set(self._universe)
            out_sets[id(node)] = set(self._universe)
        if entry is not None and entry.is_reachable:
            in_sets[id(entry)] = set(seed)
        changed = True
        while changed:
            changed = False
            for node in nodes:
                if node is entry:
                    new_in = set(seed)
                else:
                    preds = [p for p in node.predecessors if p.is_reachable]
                    if not preds:
                        new_in = set(seed)
                    else:
                        new_in = set(out_sets[id(preds[0])])
                        for pred in preds[1:]:
                            new_in &= out_sets[id(pred)]
                out = set(new_in)
                for assigned in self._node_assignments(node):
                    out.add(assigned)
                if new_in != in_sets[id(node)] or out != out_sets[id(node)]:
                    in_sets[id(node)] = new_in
                    out_sets[id(node)] = out
                    changed = True
        self.in_sets = in_sets

    def assigned_before(self, node: CFGNode, op_index: Optional[int] = None) -> set[LocalVariable]:
        """Locals definitely assigned when entering ``node`` / before op i."""
        assigned = set(self.in_sets.get(id(node), self._universe))
        ops = node.ir_operations
        limit = len(ops) if op_index is None else min(op_index, len(ops))
        for op in ops[:limit]:
            var = _assigned_local(op)
            if var is not None:
                assigned.add(var)
        if op_index is None:
            for var in self._node_assignments(node):
                assigned.add(var)
        return assigned


def uses_before_assignment(
    function: FunctionLike,
    analysis: DefiniteAssignment,
    candidates: Optional[set[int]] = None,
) -> list[tuple[LocalVariable, CFGNode, int, Operation]]:
    """All uses of body locals that are not definitely assigned yet.

    Returns ``(var, node, op_index, op)`` tuples in CFG order.  ``candidates``
    optionally restricts the analysis to specific variable ids.
    """
    results: list[tuple[LocalVariable, CFGNode, int, Operation]] = []
    for node in function.nodes:
        if not node.is_reachable:
            continue
        assigned = set(analysis.in_sets.get(id(node), set(analysis.seeded)))
        for idx, op in enumerate(node.ir_operations):
            for var in _directly_used_locals(op):
                if var in assigned:
                    continue
                if candidates is not None and id(var) not in candidates:
                    continue
                results.append((var, node, idx, op))
            assigned_local = _assigned_local(op)
            if assigned_local is not None:
                assigned.add(assigned_local)
        for extra in analysis._node_assignments(node):
            assigned.add(extra)
    return results


# ---------------------------------------------------------------------- types


def is_storage_pointer_candidate(var: LocalVariable) -> bool:
    """A local that can alias contract storage: struct/array/mapping typed and
    storage-located (or default-located, which meant storage before solc 0.5)."""
    if var.location not in (None, "storage"):
        return False
    var_type = var.type
    if isinstance(var_type, (ArrayType, MappingType)):
        return True
    if isinstance(var_type, UserDefinedType) and isinstance(var_type.type, Structure):
        return True
    return False


def is_variable_length_type(var_type: Optional[Type]) -> bool:
    """Types whose ``abi.encodePacked`` output length is data-dependent."""
    if var_type is None:
        return False
    if isinstance(var_type, ElementaryType):
        return var_type.name in ("string", "bytes")
    if isinstance(var_type, ArrayType):
        if var_type.is_dynamic:
            return True
        return is_variable_length_type(var_type.type)
    if isinstance(var_type, TupleType):
        return any(is_variable_length_type(elem) for elem in var_type.types)
    return False
