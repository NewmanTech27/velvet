"""SolIR-SSA transform (spec/architecture.md §6.5).

For every function/modifier, builds ``node.ir_operations_ssa`` from
``node.ir_operations``:

- **Versioning** — every named variable (local/state) and every IR variable
  (TMP/REF/TUPLE) is renamed so each is assigned exactly once
  (``x``, ``x_1``, ``x_2``, ...).  SSA variables keep a
  ``non_ssa_version`` backlink to their plain-IR origin plus an
  ``ssa_index`` version number.
- **φ-functions at control-flow merges** — placed with the classic
  iterated-dominance-frontier algorithm over the function CFG.
- **φ-functions for state variables at function entry** — a state
  variable's value may be the initial value or the value left by any
  previous transaction; entry phis (``origin="entry"``) model that with a
  single unversioned candidate denoting "the outside world".
- **φ-functions for state variables after every external call**
  (``origin="external_call"``) — high/low-level external calls may reenter
  and mutate state, so every state variable used in the function receives a
  fresh version after the call.
- **Storage-alias φ-functions** (``origin="alias"``) — a local ``storage``
  variable may alias several state variables (e.g. ``S storage r = c ? a :
  b``; the parser lowers the ternary, so both assignments appear and the
  may-alias set is the union).  A write through such an alias inserts
  φ-functions for **all** candidate state variables.

Documented pragmatic choices: writes *through* a ``ReferenceVariable``
(e.g. ``balances[x] = 1``) do not version the root variable inline (the
dependency analysis resolves REF roots instead); IR variables are versioned
per definition without phis (single static definition); unreachable nodes
receive no SSA view.

Original clean-room implementation.
"""

from __future__ import annotations

import copy
import logging
from typing import Any, Optional

from velvet.core.function import FunctionLike
from velvet.core.variables import LocalVariable, StateVariable, Variable
from velvet.ir.operations import (
    HighLevelCall,
    LibraryCall,
    LowLevelCall,
    Operation,
    OperationWithLValue,
    Phi,
    Send,
    Transfer,
)
from velvet.ir.variables import IRVariable, ReferenceVariable, root_base

logger = logging.getLogger("velvet.ir.ssa")

_EXTERNAL_CALL_KINDS = (HighLevelCall, LowLevelCall, Transfer, Send)


def non_ssa_version_of(variable: Any) -> Any:
    """Return the plain-IR origin of an SSA variable (or itself)."""
    return getattr(variable, "non_ssa_version", None) or variable


def make_ssa_version(variable: Any, index: int) -> Any:
    """Clone ``variable`` as SSA version ``index`` (``name_index``)."""
    clone = object.__new__(variable.__class__)
    clone.__dict__ = dict(variable.__dict__)
    clone.name = f"{variable.name}_{index}"
    clone.non_ssa_version = variable
    clone._ssa_index = index
    return clone


# ------------------------------------------------------------- alias analysis
def storage_aliases(function: FunctionLike) -> dict[LocalVariable, set[StateVariable]]:
    """May-alias sets: local storage variable -> possible state variables.

    Forward fixpoint over the function's (plain) IR: an assignment
    ``S = <state var / REF rooted in a state var / other alias>`` unions the
    targets.  Conditional assignments union naturally (parser-lowered CFG).
    """
    from velvet.ir.operations import Assignment

    aliases: dict[LocalVariable, set[StateVariable]] = {}

    def targets_of(rvalue: Any) -> set[StateVariable]:
        root = root_base(rvalue)
        if isinstance(root, StateVariable):
            return {root}
        if isinstance(root, LocalVariable) and root.is_storage:
            return aliases.get(root, set())
        return set()

    changed = True
    while changed:
        changed = False
        for node in function.nodes:
            for op in node.ir_operations:
                if not isinstance(op, Assignment):
                    continue
                lvalue = op.lvalue
                if not (isinstance(lvalue, LocalVariable) and lvalue.is_storage):
                    continue
                targets = targets_of(op.rvalue)
                if not targets:
                    continue
                current = aliases.setdefault(lvalue, set())
                if not targets.issubset(current):
                    current |= targets
                    changed = True
    return aliases


def _collect_named_variables(function: FunctionLike) -> list[Variable]:
    """Local/state variables used by the function's IR, in first-use order."""
    seen: set[int] = set()
    result: list[Variable] = []
    for node in function.nodes:
        for op in node.ir_operations:
            for var in op.used:
                if isinstance(var, (LocalVariable, StateVariable)) and id(var) not in seen:
                    seen.add(id(var))
                    result.append(var)
            # Writing through a REF also "uses" the root named variable.
            lvalue = op.lvalue
            if isinstance(lvalue, ReferenceVariable):
                root = root_base(lvalue)
                if (
                    isinstance(root, (LocalVariable, StateVariable))
                    and id(root) not in seen
                ):
                    seen.add(id(root))
                    result.append(root)
    return result


class _SSABuilder:
    """Builds the SSA view of one function."""

    def __init__(self, function: FunctionLike) -> None:
        self._func = function
        self._nodes = [n for n in function.nodes if n.is_reachable]
        self._named = _collect_named_variables(function)
        self._state_vars = [v for v in self._named if isinstance(v, StateVariable)]
        self._aliases = storage_aliases(function)
        # per-node planned actions in emission order
        self._actions: dict[int, list[tuple[str, Any]]] = {}
        self._merge_phis: dict[int, list[Phi]] = {}
        # renaming state
        self._stacks: dict[int, list[Any]] = {}
        self._counters: dict[int, int] = {}

    # ------------------------------------------------------------ dominators
    def _compute_idom(self) -> dict[int, Optional[int]]:
        """Immediate dominators (Cooper-Harvey-Kennedy) over reachable nodes."""
        nodes = self._nodes
        index = {id(n): i for i, n in enumerate(nodes)}
        entry = 0
        # reverse postorder from entry
        order: list[int] = []
        seen: set[int] = set()
        stack: list[tuple[int, bool]] = [(entry, False)]
        preds: dict[int, list[int]] = {i: [] for i in range(len(nodes))}
        succs: dict[int, list[int]] = {i: [] for i in range(len(nodes))}
        for i, node in enumerate(nodes):
            for succ in node.successors:
                j = index.get(id(succ))
                if j is not None:
                    succs[i].append(j)
                    preds[j].append(i)
        while stack:
            current, processed = stack.pop()
            if processed:
                order.append(current)
                continue
            if current in seen:
                continue
            seen.add(current)
            stack.append((current, True))
            for nxt in succs[current]:
                if nxt not in seen:
                    stack.append((nxt, False))
        rpo = list(reversed(order))
        pos = {node_idx: i for i, node_idx in enumerate(rpo)}
        idom: dict[int, Optional[int]] = {entry: None}

        def intersect(a: int, b: int) -> int:
            while a != b:
                while pos[a] > pos[b]:
                    a = idom[a]  # type: ignore[index]
                while pos[b] > pos[a]:
                    b = idom[b]  # type: ignore[index]
            return a

        changed = True
        while changed:
            changed = False
            for node_idx in rpo:
                if node_idx == entry:
                    continue
                reachable_preds = [p for p in preds[node_idx] if p in idom]
                if not reachable_preds:
                    continue
                new_idom = reachable_preds[0]
                for p in reachable_preds[1:]:
                    new_idom = intersect(new_idom, p)
                if idom.get(node_idx) != new_idom:
                    idom[node_idx] = new_idom
                    changed = True
        self._rpo = rpo
        self._preds_idx = preds
        self._succs_idx = succs
        return idom

    def _dominance_frontiers(
        self, idom: dict[int, Optional[int]]
    ) -> dict[int, set[int]]:
        df: dict[int, set[int]] = {i: set() for i in range(len(self._nodes))}
        for b in self._rpo:
            preds = [p for p in self._preds_idx[b] if p in idom]
            if len(preds) < 2:
                continue
            for p in preds:
                runner: Optional[int] = p
                while runner is not None and runner != idom.get(b):
                    df[runner].add(b)
                    runner = idom.get(runner)
        return df

    # -------------------------------------------------------- action planning
    @staticmethod
    def _is_external_call(op: Operation) -> bool:
        return isinstance(op, _EXTERNAL_CALL_KINDS) and not isinstance(op, LibraryCall)

    def _aliased_state_writes(self, op: Operation) -> list[StateVariable]:
        """State vars aliased to the storage local this op writes *through*.

        Rebinding the local (``ref = other`` — an Assignment to the local
        itself) does not write state; only writes through the alias
        (``ref.push(x)``, ``ref[i] = x``, ``ref.field = x``) do.
        """
        from velvet.ir.operations import Assignment

        lvalue = op.lvalue
        if lvalue is None:
            return []
        if isinstance(lvalue, ReferenceVariable):
            root = root_base(lvalue)
        else:
            root = lvalue
            if isinstance(op, Assignment):
                return []  # plain rebind of the storage local
        if isinstance(root, LocalVariable) and root.is_storage:
            return sorted(self._aliases.get(root, ()), key=lambda v: v.name)
        return []

    def _plan_actions(self) -> None:
        for node in self._nodes:
            actions: list[tuple[str, Any]] = []
            for op in node.ir_operations:
                actions.append(("op", op))
                if self._is_external_call(op):
                    for sv in self._state_vars:
                        actions.append(("external_call_phi", sv))
                for sv in self._aliased_state_writes(op):
                    actions.append(("alias_phi", sv))
            self._actions[id(node)] = actions

    # ------------------------------------------------------------ phi placement
    def _definition_sites(self) -> dict[int, set[int]]:
        """var key -> node indices defining it (direct writes + planned phis)."""
        sites: dict[int, set[int]] = {}

        def add(var: Variable, node_idx: int) -> None:
            sites.setdefault(id(var), set()).add(node_idx)

        for i, node in enumerate(self._nodes):
            for kind, payload in self._actions[id(node)]:
                if kind == "op":
                    lvalue = payload.lvalue
                    if isinstance(lvalue, (LocalVariable, StateVariable)):
                        add(lvalue, i)
                else:  # planned phi defines its variable
                    add(payload, i)
            if i == 0:
                for sv in self._state_vars:  # entry phis are definitions
                    add(sv, i)
        return sites

    def _place_merge_phis(self, df: dict[int, set[int]]) -> None:
        """Iterated-DF phi placement; pre-creates Phi ops so predecessors
        can feed candidates during the renaming walk."""
        sites = self._definition_sites()
        nodes = self._nodes
        for var in self._named:
            worklist = list(sites.get(id(var), ()))
            placed: set[int] = set()
            while worklist:
                n = worklist.pop()
                for d in df.get(n, ()):
                    if d in placed:
                        continue
                    placed.add(d)
                    node = nodes[d]
                    phi = Phi(None, [], origin="merge")
                    phi.node = node
                    phi._phi_variable = var  # type: ignore[attr-defined]
                    self._merge_phis.setdefault(id(node), []).append(phi)
                    if d not in sites.get(id(var), set()):
                        sites.setdefault(id(var), set()).add(d)
                        worklist.append(d)

    # ---------------------------------------------------------------- renaming
    def _current(self, var: Any) -> Any:
        """Current SSA version of ``var`` (unversioned if never defined)."""
        if not isinstance(var, Variable):
            return var
        if not isinstance(var, (LocalVariable, StateVariable, IRVariable)):
            return var  # Constant / SolidityVariable stay singletons
        stack = self._stacks.get(id(var))
        if stack:
            return stack[-1]
        return var

    def _new_version(self, var: Variable) -> Any:
        key = id(var)
        index = self._counters.get(key, 0) + 1
        self._counters[key] = index
        clone = make_ssa_version(var, index)
        self._stacks.setdefault(key, []).append(clone)
        return clone

    def _remap_op(self, op: Operation, define: Any) -> Operation:
        clone = copy.copy(op)
        for slot in op._read_slots:
            value = getattr(op, slot, None)
            if isinstance(value, list):
                setattr(clone, slot, [self._current(v) for v in value])
            elif value is not None:
                setattr(clone, slot, self._current(value))
        lvalue = op.lvalue
        if lvalue is not None and isinstance(lvalue, Variable):
            if isinstance(clone, OperationWithLValue):
                clone.set_lvalue(define(lvalue))
        clone.expression = op.expression
        clone.node = op.node
        return clone

    def _rename(self) -> None:
        idom = self._compute_idom()
        df = self._dominance_frontiers(idom)
        self._plan_actions()
        self._place_merge_phis(df)

        # dominator tree children
        children: dict[int, list[int]] = {i: [] for i in range(len(self._nodes))}
        for node_idx, parent in idom.items():
            if parent is not None:
                children[parent].append(node_idx)
        entry_id = id(self._nodes[0])
        pushed: list[tuple[int, int]] = []  # (var key, count) per rename frame

        def new_version_tracked(var: Variable) -> Any:
            before = len(self._stacks.get(id(var), ()))
            clone = self._new_version(var)
            pushed.append((id(var), len(self._stacks[id(var)]) - before))
            return clone

        def visit(node_idx: int) -> None:
            node = self._nodes[node_idx]
            node_id = id(node)
            frame_start = len(pushed)
            ssa_ops: list[Operation] = []

            # 1. entry phis for state variables (origin "entry")
            if node_id == entry_id:
                for sv in self._state_vars:
                    lvalue = new_version_tracked(sv)
                    phi = Phi(lvalue, [sv], origin="entry")
                    phi.node = node
                    ssa_ops.append(phi)

            # 2. merge phis (pre-created; candidates fed by predecessors)
            for phi in self._merge_phis.get(node_id, ()):
                var = phi._phi_variable  # type: ignore[attr-defined]
                phi.set_lvalue(new_version_tracked(var))
                ssa_ops.append(phi)

            # 3. planned actions
            for kind, payload in self._actions[node_id]:
                if kind == "op":
                    ssa_ops.append(self._remap_op(payload, new_version_tracked))
                else:  # external_call / alias phi: candidate = pre-call version
                    var = payload
                    candidate = self._current(var)
                    lvalue = new_version_tracked(var)
                    phi = Phi(lvalue, [candidate], origin=kind[: -len("_phi")])
                    phi.node = node
                    ssa_ops.append(phi)

            node.ir_operations_ssa = ssa_ops

            # 4. feed successors' merge phis with current versions
            for succ_idx in self._succs_idx[node_idx]:
                succ = self._nodes[succ_idx]
                for phi in self._merge_phis.get(id(succ), ()):
                    var = phi._phi_variable  # type: ignore[attr-defined]
                    phi.candidates.append(self._current(var))

            # 5. recurse into dominated children, then pop our versions
            for child in children[node_idx]:
                visit(child)
            for key, count in pushed[frame_start:]:
                for _ in range(count):
                    self._stacks[key].pop()
            del pushed[frame_start:]

        visit(0)


def convert_function_ssa(function: FunctionLike) -> None:
    """Build ``ir_operations_ssa`` for one function/modifier (never raises)."""
    try:
        if not function.nodes or not any(
            n.ir_operations for n in function.nodes if n.is_reachable
        ):
            return
        _SSABuilder(function)._rename()
    except Exception:  # noqa: BLE001 - degrade per spec §12
        logger.warning(
            "SSA construction failed for %s; leaving empty SSA view",
            function.canonical_name,
            exc_info=True,
        )
        for node in function.nodes:
            node.ir_operations_ssa = []


def convert_unit_ssa(unit: Any) -> None:
    """Build the SSA view for every function/modifier of a unit."""
    for function in unit.functions_and_modifiers:
        convert_function_ssa(function)
