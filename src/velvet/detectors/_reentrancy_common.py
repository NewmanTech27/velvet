"""Shared core analysis for the reentrancy detector family.

`reentrancy-eth`, `reentrancy-no-eth`, `reentrancy-benign` and
`reentrancy-events` are documented (spec/detectors-catalog.md appendix A) as
variants of one reentrancy analysis with different filters; this module is
that shared core.  It locates re-enterable external interactions in a
function body and computes, per interaction:

- the state variables read on some path leading to the interaction
  (including the interaction's own operands), and
- the state variables written on some path after the interaction, and
- the events emitted on some path after the interaction,

using a may-analysis over a *composed* view of the function:

- **Modifier bodies** are inlined around the function body at their ``_``
  placeholder (statements before ``_`` run before the body, statements
  after ``_`` run after it; nesting order follows the application order).
  Interaction/write/event nodes keep pointing at the real source (the
  modifier definition site).  When the same modifier is applied to several
  functions, each function is analyzed independently, so a modifier-body
  interaction yields at most one finding per (interaction, function).
- **Internal calls are inlined transitively**, up to ``_MAX_INLINE_DEPTH``
  levels: plain ``InternalCall`` ops (resolved to the most-derived
  override within the contract under analysis, since unqualified internal
  calls dispatch virtually) and base-qualified static calls
  (``Base.f(args)``, which compile to internal jumps — their destination
  is a contract *type*, not an address value).  A callee's interactions
  are treated as occurring at the call site and its state
  reads/writes/events participate in the caller's ordering; per
  interaction, position-aware facts collected along the inlining path
  (reads before / writes / events after) are merged over every call site
  reaching it (may-analysis).  Recursion along the chain is detected and
  skipped with a debug log (intra-procedural fallback).  Guard evaluation
  honors mutexes recognized at any level of the path.
- **ERC-7201 "diamond storage"** is modeled through canonical *region
  tokens*: writes through a local storage pointer (``$.field = …``) count
  as writes of the storage region (keyed by the struct type), and reads
  through the pointer count as region reads, so reads-before/writes-after
  comparisons match across a call chain even though no declared state
  variable is involved.
- State variables carrying the NatSpec tag
  ``@custom:security non-reentrant`` (spec/architecture.md §11.3) are
  excluded from the "state variables written after call" classification;
  detectors opt in by passing :func:`natspec_tagged_state_variables`.
- **Reentrancy guards (mutexes) are recognized** and interactions behind
  them are suppressed: a state variable acts as a guard for an interaction
  when, on *every* path of the composed view, it is (a) checked by a guard
  condition (``require``/``assert`` or an ``if`` whose then-branch reverts)
  before the interaction, (b) written a "locked" value inconsistent with
  the checked requirement before the interaction, and (c) written an
  "unlocked" value consistent with the requirement somewhere after the
  interaction.  Both boolean (``require(!locked); locked = true; ...``)
  and unsigned-enum (``require(_status != ENTERED); _status = ENTERED;
  ...``) mutex styles are recognized; the check must dominate the
  interaction, so a guard present on only some paths does not suppress.
  Guard-variable writes themselves are mutex machinery and never count as
  writes-after for any interaction of the function.

Original clean-room implementation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

from velvet.core.cfg_node import CFGNode, NodeKind
from velvet.core.expressions import Literal
from velvet.core.function import FunctionLike
from velvet.core.variables import (
    Constant,
    LocalVariable,
    SolidityVariable,
    StateVariable,
    Variable,
)
from velvet.ir.operations import (
    Assignment,
    Binary,
    Condition,
    EventCall,
    HighLevelCall,
    InternalCall,
    LibraryCall,
    LowLevelCall,
    Send,
    SolidityCall,
    Transfer,
    TypeConversion,
    Unary,
)
from velvet.ir.variables import ReferenceVariable, root_base
from velvet.parsing.natspec import docstring_above, has_tag

logger = logging.getLogger("velvet.detectors.reentrancy")


def _is_constant_zero(value: Any) -> bool:
    if not isinstance(value, Constant):
        return False
    try:
        return int(str(value.value), 0) == 0
    except (TypeError, ValueError):
        return False


def _sends_ether(op: Any) -> bool:
    """True when the interaction may move Ether with it."""
    if isinstance(op, (Transfer, Send)):
        return True
    call_value = getattr(op, "call_value", None)
    return call_value is not None and not _is_constant_zero(call_value)


def _classify_interaction(op: Any) -> Optional[tuple[bool, bool]]:
    """Classify an op as a re-enterable interaction.

    Returns ``(sends_eth, gas_bounded)`` or None when the op is not an
    interaction through which attacker code can re-enter and change state.
    """
    if isinstance(op, LibraryCall):
        # Trusted code executing in the caller's context.
        return None
    if isinstance(op, HighLevelCall):
        if _qualified_static_callee(op) is not None:
            # Base.f() qualification compiles to an internal jump (the
            # destination is a contract *type*); it is inlined as an
            # internal call, not treated as a re-enterable external call.
            return None
        target = op.function
        if target is not None and (target.view or target.pure):
            # Compiled to STATICCALL: no state-changing re-entry.
            return None
        return _sends_ether(op), False
    if isinstance(op, LowLevelCall):
        if op.function_name == "staticcall":
            return None
        # call / delegatecall / callcode all run external, state-changing code.
        return _sends_ether(op), False
    if isinstance(op, (Transfer, Send)):
        # Fixed 2300-gas stipend: re-enterable in principle, gas-bounded.
        return True, True
    return None


def _read_state_vars(ops: list[Any]) -> Iterator[StateVariable]:
    """State variables read by a sequence of ops (REF roots included)."""
    for op in ops:
        for var in op.read:
            candidates = [var]
            if isinstance(var, ReferenceVariable):
                root = root_base(var)
                if root is not var:
                    candidates.append(root)
            for candidate in candidates:
                if isinstance(candidate, StateVariable):
                    yield candidate


def _written_state_var(op: Any) -> Optional[StateVariable]:
    """The state variable written by an op (through REF roots), if any."""
    lvalue = op.lvalue
    if lvalue is None:
        return None
    if isinstance(lvalue, StateVariable):
        return lvalue
    if isinstance(lvalue, ReferenceVariable):
        root = root_base(lvalue)
        if isinstance(root, StateVariable):
            return root
    return None


#: Canonical tokens for ERC-7201-style storage regions, keyed by the
#: storage struct type name.  Diamond-storage reads/writes go through a
#: local storage pointer (``AppStorage storage $ = _getAppStorage()``), so
#: they never resolve to a declared state variable; the token lets
#: reads-before / writes-after comparisons match across a call chain.
_STORAGE_REGIONS: dict[str, StateVariable] = {}


def _storage_region(var: Any) -> Optional[StateVariable]:
    """The canonical region token for a storage-pointer-rooted variable.

    Returns None for plain state variables (handled by the normal path) and
    for non-storage locals.
    """
    root = root_base(var) if isinstance(var, ReferenceVariable) else var
    if isinstance(root, StateVariable) or not isinstance(root, LocalVariable):
        return None
    if getattr(root, "location", "") != "storage":
        return None
    type_name = str(getattr(root, "type", "") or "").strip()
    if not type_name:
        return None
    token = _STORAGE_REGIONS.get(type_name)
    if token is None:
        token = StateVariable()
        token.name = type_name
        _STORAGE_REGIONS[type_name] = token
    return token


def _state_or_region(var: Any) -> Optional[StateVariable]:
    """``var`` as a state variable, or its storage-region token."""
    if isinstance(var, StateVariable):
        return var
    return _storage_region(var)


def _written_state_var_or_region(op: Any) -> Optional[StateVariable]:
    var = _written_state_var(op)
    if var is not None:
        return var
    # Only genuine assignments *through* a storage pointer (`$.field = …`)
    # count as region writes.  Reference-construction ops (Member/Index,
    # which surface their produced reference as the lvalue) and the pointer
    # initialization (`$ := _getXStorage()`) are not state mutations.
    if isinstance(op, Assignment) and isinstance(op.lvalue, ReferenceVariable):
        return _storage_region(op.lvalue)
    return None


def _read_state_vars_or_regions(ops: list[Any]) -> Iterator[StateVariable]:
    """Like :func:`_read_state_vars`, plus storage-region tokens."""
    for op in ops:
        seen: set[int] = set()
        for var in _read_state_vars([op]):
            seen.add(id(var))
            yield var
        for var in op.read:
            region = _storage_region(var)
            if region is not None and id(region) not in seen:
                seen.add(id(region))
                yield region


def owner_function(node: CFGNode, default: FunctionLike) -> FunctionLike:
    """The function-like whose body hosts ``node`` (modifier-aware)."""
    owner = getattr(node, "function", None)
    return owner if isinstance(owner, FunctionLike) else default


def expand_terminal_sources(variables: list[Any], function: FunctionLike) -> list[Any]:
    """Expand TMP/REF/TUPLE values to their source variables.

    Like :func:`velvet.analyses.read_write.expand_read_variables`, but state
    variables and builtins are *terminal*: they are reported as sources even
    when the function also writes them (their in-function definition is not
    chased).  This answers "does this value read state X?" rather than
    "what was state X last computed from?".
    """
    defining: dict[int, Any] = {}
    for node in function.all_nodes:
        for op in node.ir_operations:
            if op.lvalue is not None:
                defining[id(op.lvalue)] = op

    result: list[Any] = []
    seen: set[int] = set()
    stack = list(variables)
    while stack:
        var = stack.pop()
        if var is None or id(var) in seen:
            continue
        seen.add(id(var))
        origin = getattr(var, "non_ssa_version", None) or var
        if isinstance(origin, (StateVariable, SolidityVariable, Constant)):
            if not any(v is origin for v in result):
                result.append(origin)
            continue
        op = defining.get(id(var)) or defining.get(id(origin))
        if op is None:
            if isinstance(origin, Variable) and not any(v is origin for v in result):
                result.append(origin)
        else:
            stack.extend(op.read)
    return result


# ------------------------------------------------------------- graph views
@dataclass
class _GraphView:
    """A function's CFG with applied modifier bodies spliced in at ``_``.

    ``succ``/``pred`` are keyed by ``id(node)`` and *overlay* the real CFG
    edges: nodes are shared with the model (findings keep pointing at the
    real source), only the edge maps are virtual, so the same modifier
    object can be spliced into several functions independently.
    """

    nodes: list[CFGNode]
    succ: dict[int, list[CFGNode]]
    pred: dict[int, list[CFGNode]]


def _vlink(view: _GraphView, src: CFGNode, dst: CFGNode) -> None:
    if dst not in view.succ[id(src)]:
        view.succ[id(src)].append(dst)
    if src not in view.pred[id(dst)]:
        view.pred[id(dst)].append(src)


def _vunlink(view: _GraphView, src: CFGNode, dst: CFGNode) -> None:
    if dst in view.succ[id(src)]:
        view.succ[id(src)].remove(dst)
    if src in view.pred[id(dst)]:
        view.pred[id(dst)].remove(src)


def _exits_of(nodes: list[CFGNode], view: _GraphView) -> list[CFGNode]:
    """Terminal nodes through which control may leave ``nodes``.

    ``THROW`` (revert) nodes abort the whole transaction, so control never
    continues past them into post-``_`` code or outer modifiers.
    """
    return [
        n for n in nodes if not view.succ[id(n)] and n.kind is not NodeKind.THROW
    ]


def _build_graph_view(function: FunctionLike) -> _GraphView:
    """Compose ``function``'s CFG with its applied modifiers' bodies.

    Modifiers apply outside-in following the source order: for
    ``function f() A B``, execution is ``A.pre -> B.pre -> body -> B.post
    -> A.post``.  Each modifier is spliced at its ``_`` placeholder node:
    the placeholder's outgoing edges are rewired to the current (inner)
    entry, and the current exits are rewired to the placeholder's original
    successors (the post-``_`` part).  A modifier without a placeholder is
    treated as running entirely before the body.
    """
    view = _GraphView(nodes=list(function.nodes), succ={}, pred={})
    for node in function.nodes:
        view.succ[id(node)] = list(node.successors)
        view.pred[id(node)] = list(node.predecessors)

    entries = [function.entry_point] if function.entry_point is not None else []
    exits = _exits_of(function.nodes, view)

    seen_modifiers: set[int] = set()
    for modifier in reversed(function.modifiers):
        if (
            id(modifier) in seen_modifiers
            or not modifier.is_implemented
            or not modifier.nodes
            or modifier.entry_point is None
        ):
            continue
        seen_modifiers.add(id(modifier))
        for node in modifier.nodes:
            view.nodes.append(node)
            view.succ[id(node)] = list(node.successors)
            view.pred[id(node)] = list(node.predecessors)
        placeholders = [
            n for n in modifier.nodes if n.kind is NodeKind.PLACEHOLDER
        ]
        if not placeholders:
            # No `_`: the body is dead code in practice; wire the modifier
            # wholly before it (conservative).
            for exit_node in _exits_of(modifier.nodes, view):
                for entry in entries:
                    _vlink(view, exit_node, entry)
            entries = [modifier.entry_point]
            continue
        for placeholder in placeholders:
            after = list(view.succ[id(placeholder)])
            # The inner body runs where `_` sits.
            for entry in entries:
                _vlink(view, placeholder, entry)
            # Inner exits continue into the post-`_` part of the modifier.
            for exit_node in exits:
                for target in after:
                    _vlink(view, exit_node, target)
            for target in after:
                _vunlink(view, placeholder, target)
        entries = [modifier.entry_point]
        exits = _exits_of(modifier.nodes, view)
    return view


@dataclass
class _InteractionRecord:
    """One re-enterable interaction reachable from a helper, with the
    data-flow facts collected relative to the helper's own entry.

    ``checkpoints`` lists the guard-evaluation positions along the inlining
    path: the interaction itself plus each internal-call site through which
    it was lifted (``(view, owner function-like, node, op index)``).  Mutex
    recognition evaluates them lazily in :func:`_apply_guard_suppression`.
    """

    owner_view: _GraphView
    owner: FunctionLike
    node: CFGNode
    op_index: int
    op: Any
    sends_eth: bool
    gas_bounded: bool
    reads_before: list[StateVariable] = field(default_factory=list)
    writes_after: list[tuple[StateVariable, CFGNode]] = field(default_factory=list)
    events_after: list[tuple[EventCall, CFGNode]] = field(default_factory=list)
    checkpoints: list[tuple[_GraphView, FunctionLike, CFGNode, int]] = field(
        default_factory=list
    )


@dataclass
class _HelperView:
    """Summary of a directly-called internal function, for bounded inlining.

    Facts (reads/writes/events/interactions) are transitive may-unions over
    the callee's own body (modifiers spliced) and, up to
    ``_MAX_INLINE_DEPTH`` levels of nested internal calls, its callees.
    """

    callee: FunctionLike
    view: _GraphView
    #: (node, op index, op, sends_eth, gas_bounded) per re-enterable call.
    interactions: list[tuple[CFGNode, int, Any, bool, bool]] = field(
        default_factory=list
    )
    #: State vars the callee may read (transitive union).
    reads: list[StateVariable] = field(default_factory=list)
    writes: list[tuple[StateVariable, CFGNode]] = field(default_factory=list)
    events: list[tuple[EventCall, CFGNode]] = field(default_factory=list)
    #: Nested inline sites of this callee: ``(id(node), op index)`` -> view.
    sites: dict[tuple[int, int], "_HelperView"] = field(default_factory=dict)
    #: Per-interaction records with facts relative to this helper's entry.
    records: list[_InteractionRecord] = field(default_factory=list)


#: Bound on nested internal-call inlining (recursion and very deep chains
#: fall back to the intra-procedural approximation).
_MAX_INLINE_DEPTH = 8


def _ancestry(contract: Any) -> set[int]:
    """``id()``s of ``contract`` and its transitive base contracts."""
    seen: set[int] = set()
    stack = [contract]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        stack.extend(current.inheritance)
    return seen


def _resolve_virtual(callee: FunctionLike, contract: Any) -> FunctionLike:
    """Resolve an unqualified internal call to the most-derived override.

    Inside ``contract`` (the contract under analysis), an internal call to a
    virtual function dispatches to the most-derived implementation, not the
    statically resolved one.  Returns ``callee`` unchanged when there is no
    override in ``contract``'s hierarchy (or no contract context is given).
    """
    if contract is None:
        return callee
    declarer = callee.contract_declarer
    if declarer is None:
        return callee
    if declarer is not contract and id(declarer) not in _ancestry(contract):
        return callee
    candidate = contract.get_function_from_signature(callee.signature)
    if candidate is None or candidate is callee or not candidate.is_implemented:
        return callee
    return candidate


def _qualified_static_callee(op: Any) -> Optional[FunctionLike]:
    """The target of a base-qualified static call (``Base.f(args)``).

    Such calls compile to internal jumps (the destination is a contract
    *type*, not an address value), so their callee's body can be inlined
    like an :class:`InternalCall`.  Returns None for regular external calls
    (address-typed destinations) and for non-call ops.
    """
    from velvet.core.contract import Contract  # local import: avoid cycle

    if not isinstance(op, HighLevelCall) or not isinstance(op.destination, Contract):
        return None
    function = op.function
    if not isinstance(function, FunctionLike):
        return None
    return function


def _summarize_helper(
    callee: FunctionLike,
    chain: tuple[int, ...] = (),
    cache: Optional[dict[int, _HelperView]] = None,
    contract: Any = None,
) -> _HelperView:
    view = _build_graph_view(callee)
    helper = _HelperView(callee=callee, view=view)

    def add_read(var: StateVariable) -> None:
        if not any(v is var for v in helper.reads):
            helper.reads.append(var)

    def add_write(var: StateVariable, node: CFGNode) -> None:
        if not any(v is var for v, _n in helper.writes):
            helper.writes.append((var, node))

    def add_event(op: EventCall, node: CFGNode) -> None:
        if not any(e is op for e, _n in helper.events):
            helper.events.append((op, node))

    for node in view.nodes:
        for index, op in enumerate(node.ir_operations):
            classified = _classify_interaction(op)
            if classified is not None:
                sends_eth, gas_bounded = classified
                helper.interactions.append((node, index, op, sends_eth, gas_bounded))
            if isinstance(op, EventCall):
                add_event(op, node)
            written = _written_state_var_or_region(op)
            if written is not None:
                add_write(written, node)
            for var in _read_state_vars_or_regions([op]):
                add_read(var)
    # Interaction operands may read state through temporaries.
    for _node, _index, op, _sends, _bounded in helper.interactions:
        for var in expand_terminal_sources(op.read, callee):
            source = _state_or_region(var)
            if source is not None:
                add_read(source)

    # Nested internal calls: inline one more level (bounded by the chain).
    if len(chain) < _MAX_INLINE_DEPTH:
        helper.sites = _inline_sites(
            callee, view, contract=contract, chain=chain, cache=cache
        )
    for nested in {id(s): s for s in helper.sites.values()}.values():
        for h_node, h_index, h_op, sends_eth, gas_bounded in nested.interactions:
            if not any(h_op is op for _n, _i, op, _s, _b in helper.interactions):
                helper.interactions.append(
                    (h_node, h_index, h_op, sends_eth, gas_bounded)
                )
        for var, wnode in nested.writes:
            add_write(var, wnode)
        for event_op, enode in nested.events:
            add_event(event_op, enode)
        for var in nested.reads:
            add_read(var)

    # Per-interaction records, with facts relative to this helper's entry.
    own_nodes = {id(node) for node in view.nodes}
    for node, index, op, sends_eth, gas_bounded in list(helper.interactions):
        if id(node) in own_nodes:
            reads = _collect_reads_before(view, {}, node, index, op, callee)
            writes, events = _collect_after(view, {}, node, index)
            _append_record(
                helper,
                _InteractionRecord(
                    owner_view=view,
                    owner=callee,
                    node=node,
                    op_index=index,
                    op=op,
                    sends_eth=sends_eth,
                    gas_bounded=gas_bounded,
                    reads_before=reads,
                    writes_after=writes,
                    events_after=events,
                    checkpoints=[(view, callee, node, index)],
                ),
            )
    for (site_node_id, site_index), nested in helper.sites.items():
        site_node = next(
            node for node in view.nodes if id(node) == site_node_id
        )
        site_op = site_node.ir_operations[site_index]
        hop_reads = _collect_reads_before(
            view, helper.sites, site_node, site_index, site_op, callee
        )
        hop_writes, hop_events = _collect_after(
            view, helper.sites, site_node, site_index
        )
        for nested_record in nested.records:
            lifted = _InteractionRecord(
                owner_view=nested_record.owner_view,
                owner=nested_record.owner,
                node=nested_record.node,
                op_index=nested_record.op_index,
                op=nested_record.op,
                sends_eth=nested_record.sends_eth,
                gas_bounded=nested_record.gas_bounded,
                reads_before=list(nested_record.reads_before),
                writes_after=list(nested_record.writes_after),
                events_after=list(nested_record.events_after),
                checkpoints=list(nested_record.checkpoints)
                + [(view, callee, site_node, site_index)],
            )
            for var in hop_reads:
                if not any(v is var for v in lifted.reads_before):
                    lifted.reads_before.append(var)
            for var, wnode in hop_writes:
                if not any(v is var for v, _n in lifted.writes_after):
                    lifted.writes_after.append((var, wnode))
            for event_op, enode in hop_events:
                if not any(e is event_op for e, _n in lifted.events_after):
                    lifted.events_after.append((event_op, enode))
            _append_record(helper, lifted)
    return helper


def _append_record(helper: _HelperView, record: _InteractionRecord) -> None:
    """Add ``record`` to ``helper.records``, merging per interaction op."""
    for existing in helper.records:
        if existing.op is not record.op:
            continue
        for var in record.reads_before:
            if not any(v is var for v in existing.reads_before):
                existing.reads_before.append(var)
        for var, wnode in record.writes_after:
            if not any(v is var for v, _n in existing.writes_after):
                existing.writes_after.append((var, wnode))
        for event_op, enode in record.events_after:
            if not any(e is event_op for e, _n in existing.events_after):
                existing.events_after.append((event_op, enode))
        existing.checkpoints.extend(record.checkpoints)
        return
    helper.records.append(record)


def _inline_sites(
    function: FunctionLike,
    view: _GraphView,
    contract: Any = None,
    chain: tuple[int, ...] = (),
    cache: Optional[dict[int, _HelperView]] = None,
) -> dict[tuple[int, int], _HelperView]:
    """Direct internal calls of ``function`` eligible for bounded inlining.

    Keyed by ``(id(node), op index)``.  Both plain ``InternalCall`` ops and
    base-qualified static calls (``Base.f(args)``, which compile to internal
    jumps) are eligible; unqualified calls are resolved to the most-derived
    override within ``contract`` (the contract under analysis).  Recursion
    along the inlining chain is detected and skipped (intra-procedural
    fallback, per the documented bound).
    """
    if cache is None:
        cache = {}
    sites: dict[tuple[int, int], _HelperView] = {}
    active = chain + (id(function),)
    for node in view.nodes:
        for index, op in enumerate(node.ir_operations):
            qualified = _qualified_static_callee(op)
            if qualified is not None:
                # Explicit Base.f() qualification: statically bound already.
                callee = qualified
            elif isinstance(op, InternalCall):
                callee = op.function
                if (
                    isinstance(callee, FunctionLike)
                    and not getattr(op, "is_static", False)
                ):
                    # A plain `f(...)` internal call dispatches to the
                    # most-derived override.  Statically-bound internal
                    # calls (ancestor-qualified `Base.f(...)`, `super.f(...)`)
                    # already carry their exact target: resolving them to the
                    # most-derived override would (a) be wrong and (b) mark
                    # an override calling its own base implementation as
                    # recursive, dropping the base body (and its writes)
                    # from the inlining summary.
                    callee = _resolve_virtual(callee, contract)
            else:
                continue
            if (
                callee is None
                or not isinstance(callee, FunctionLike)
                or callee.is_constructor
                or not callee.is_implemented
                or not callee.nodes
            ):
                continue
            if id(callee) in active:
                logger.debug(
                    "reentrancy: %s is recursive along the inlining chain; "
                    "keeping intra-procedural ordering (internal call not "
                    "inlined)",
                    callee.canonical_name,
                )
                continue
            helper = cache.get(id(callee))
            if helper is None:
                helper = _summarize_helper(
                    callee, chain=active, cache=cache, contract=contract
                )
                cache[id(callee)] = helper
            sites[(id(node), index)] = helper
    return sites


# ---------------------------------------------------------------- contexts
@dataclass
class CallContext:
    """One re-enterable interaction plus its surrounding data-flow facts."""

    #: The analyzed (entry) function the finding is reported against.
    function: FunctionLike
    #: The function-like whose body hosts the interaction (``function``,
    #: one of its modifiers, or an inlined internal callee).
    owner: FunctionLike
    node: CFGNode
    op: Any
    op_index: int
    sends_eth: bool
    gas_bounded: bool
    #: State vars read on some path from entry to the interaction (incl. the
    #: interaction's own operands), in first-appearance order.
    reads_before: list[StateVariable] = field(default_factory=list)
    #: (state var, writing node) reachable after the interaction.
    writes_after: list[tuple[StateVariable, CFGNode]] = field(default_factory=list)
    #: (event op, emitting node) reachable after the interaction.
    events_after: list[tuple[EventCall, CFGNode]] = field(default_factory=list)
    #: Guard (mutex) state variables protecting this interaction, per the
    #: guard recognition documented in the module docstring.  Non-empty
    #: means re-entry is blocked: ``writes_after``/``events_after`` are
    #: then emptied by :func:`function_call_contexts` (suppression).
    guarded_by: list[StateVariable] = field(default_factory=list)

    def read_before(self, var: StateVariable) -> bool:
        return any(v is var for v in self.reads_before)


def _collect_reads_before(
    view: _GraphView,
    sites: dict[tuple[int, int], _HelperView],
    call_node: CFGNode,
    call_index: int,
    call_op: Any,
    call_owner: FunctionLike,
) -> list[StateVariable]:
    """State vars read on some path from the entry to the interaction.

    Computed over the interaction's *predecessor closure* (nodes that can
    reach it, which also handles loop back edges), plus the ops preceding it
    in its own node and its own operands.  Reads of inlined internal
    callees count as reads at their call site.
    """
    result: list[StateVariable] = []

    def add(var: StateVariable) -> None:
        if not any(v is var for v in result):
            result.append(var)

    def scan(node: CFGNode, upto: Optional[int]) -> None:
        ops = node.ir_operations if upto is None else node.ir_operations[:upto]
        for index, op in enumerate(ops):
            for var in _read_state_vars_or_regions([op]):
                add(var)
            helper = sites.get((id(node), index))
            if helper is not None:
                for var in helper.reads:
                    add(var)

    before: set[int] = set()
    stack: list[CFGNode] = list(view.pred[id(call_node)])
    while stack:
        node = stack.pop()
        if id(node) in before:
            continue
        before.add(id(node))
        stack.extend(view.pred[id(node)])
    for node in view.nodes:
        if id(node) not in before:
            continue
        scan(node, None)
    scan(call_node, call_index)
    # The interaction's own operands (e.g. a value computed from a state var).
    for var in expand_terminal_sources(call_op.read, call_owner):
        source = _state_or_region(var)
        if source is not None:
            add(source)
    return result


def _collect_after(
    view: _GraphView,
    sites: dict[tuple[int, int], _HelperView],
    call_node: CFGNode,
    call_index: int,
    safe_var_ids: frozenset[int] = frozenset(),
) -> tuple[list[tuple[StateVariable, CFGNode]], list[tuple[EventCall, CFGNode]]]:
    """State writes and event emissions reachable after the interaction.

    Writes/emit of inlined internal callees count at their call site.
    State vars in ``safe_var_ids`` (NatSpec-tagged, spec §11.3) are excluded
    from the write classification.
    """
    writes: list[tuple[StateVariable, CFGNode]] = []
    events: list[tuple[EventCall, CFGNode]] = []

    def add_write(var: StateVariable, node: CFGNode) -> None:
        if id(var) in safe_var_ids:
            return
        if not any(v is var for v, _n in writes):
            writes.append((var, node))

    def add_event(op: EventCall, node: CFGNode) -> None:
        if not any(e is op for e, _n in events):
            events.append((op, node))

    visited: set[int] = set()
    stack: list[CFGNode] = [call_node]
    while stack:
        node = stack.pop()
        if id(node) in visited:
            continue
        visited.add(id(node))
        start = call_index + 1 if node is call_node else 0
        for index in range(start, len(node.ir_operations)):
            op = node.ir_operations[index]
            if isinstance(op, EventCall):
                add_event(op, node)
            var = _written_state_var_or_region(op)
            if var is not None:
                add_write(var, node)
            helper = sites.get((id(node), index))
            if helper is not None:
                for hvar, hnode in helper.writes:
                    add_write(hvar, hnode)
                for hevent, hnode in helper.events:
                    add_event(hevent, hnode)
        stack.extend(view.succ[id(node)])
    return writes, events


# ------------------------------------------------------- guard recognition
@dataclass
class _GuardRequirement:
    """A guard condition on a state variable, at one node/op position.

    ``mode`` describes the value the variable must hold for execution to
    pass the guard: ``"eq"``/``"ne"`` (must equal/differ from ``value``) or
    ``"truthy"``/``"falsey"``.
    """

    var: StateVariable
    mode: str
    value: Any
    node: CFGNode
    op_index: int


def _invert_mode(mode: str) -> str:
    return {"eq": "ne", "ne": "eq", "truthy": "falsey", "falsey": "truthy"}[mode]


def _direct_state_var(value: Any) -> Optional[StateVariable]:
    """``value`` resolved to a state variable *itself* (no REF root chase).

    Guard conditions must name the guard variable directly: a check through
    a mapping/array/struct member (``require(!locked[id])``) is
    key-sensitive and is deliberately not treated as a mutex check.
    """
    origin = getattr(value, "non_ssa_version", None) or value
    return origin if isinstance(origin, StateVariable) else None


def _parse_literal_int(text: str) -> Optional[int]:
    stripped = text.strip().lower()
    if stripped == "true":
        return 1
    if stripped == "false":
        return 0
    try:
        return int(stripped, 0)
    except (TypeError, ValueError):
        return None


def _literal_int(value: Any) -> Optional[int]:
    """Static integer/boolean value of a literal or constant, if known."""
    origin = getattr(value, "non_ssa_version", None) or value
    if isinstance(origin, Constant):
        return _parse_literal_int(str(origin.value))
    if isinstance(origin, StateVariable) and origin.is_constant:
        initial = origin.expression_initial
        if isinstance(initial, Literal):
            return _parse_literal_int(initial.value)
    return None


def _same_value(a: Any, b: Any) -> bool:
    """True when two operands provably denote the same value."""
    int_a, int_b = _literal_int(a), _literal_int(b)
    if int_a is not None and int_b is not None:
        return int_a == int_b
    origin_a = getattr(a, "non_ssa_version", None) or a
    origin_b = getattr(b, "non_ssa_version", None) or b
    return (
        isinstance(origin_a, StateVariable)
        and isinstance(origin_b, StateVariable)
        and origin_a is origin_b
    )


def _provably_different(a: Any, b: Any) -> bool:
    """True when two operands provably denote different values."""
    int_a, int_b = _literal_int(a), _literal_int(b)
    if int_a is not None and int_b is not None:
        return int_a != int_b
    return False


def _defining_op(var: Any, owner: FunctionLike) -> Optional[Any]:
    """The *unique* op in ``owner`` writing ``var`` (None when ambiguous)."""
    found: Optional[Any] = None
    for node in owner.all_nodes:
        for op in node.ir_operations:
            if op.lvalue is var:
                if found is not None:
                    return None
                found = op
    return found


def _condition_requirements(
    condition: Any, owner: FunctionLike, seen: Optional[set[int]] = None
) -> list[tuple[StateVariable, str, Any]]:
    """Guard requirements that must hold when ``condition`` is true.

    Returns ``(state var, mode, compared value)`` triples.  Recognized
    shapes: a bare state variable (truthy), ``!x``, ``x == c`` / ``x != c``
    (either operand order), and conjunctions of those.  Anything else
    (order comparisons, disjunctions, calls, REF-rooted reads) yields no
    requirement — conservative.
    """
    if seen is None:
        seen = set()
    if condition is None or id(condition) in seen:
        return []
    seen.add(id(condition))
    origin = getattr(condition, "non_ssa_version", None) or condition
    if isinstance(origin, StateVariable):
        if origin.is_constant:
            return []
        return [(origin, "truthy", None)]
    defining = _defining_op(origin, owner)
    if defining is None:
        return []
    if isinstance(defining, (Assignment, TypeConversion)):
        return _condition_requirements(defining.rvalue, owner, seen)
    if isinstance(defining, Unary) and defining.operator == "!":
        return [
            (var, _invert_mode(mode), value)
            for var, mode, value in _condition_requirements(
                defining.rvalue, owner, seen
            )
        ]
    if isinstance(defining, Binary):
        if defining.operator == "&&":
            return _condition_requirements(
                defining.left, owner, seen
            ) + _condition_requirements(defining.right, owner, seen)
        if defining.operator in ("==", "!="):
            mode = "eq" if defining.operator == "==" else "ne"
            requirements = []
            for side, other in (
                (defining.left, defining.right),
                (defining.right, defining.left),
            ):
                var = _direct_state_var(side)
                if var is not None and not var.is_constant:
                    requirements.append((var, mode, other))
            return requirements
    return []


def _is_revert_node(node: CFGNode) -> bool:
    """True when the node aborts the transaction (``revert``/custom error)."""
    if node.kind is NodeKind.THROW:
        return True
    return any(
        isinstance(op, SolidityCall) and getattr(op.function, "name", "") == "revert"
        for op in node.ir_operations
    )


def _view_guard_checks(
    view: _GraphView, function: FunctionLike
) -> list[_GuardRequirement]:
    """All guard conditions on state variables in a (spliced) graph view.

    Two shapes are recognized:

    - ``require(cond)`` / ``assert(cond)`` — execution continues only when
      ``cond`` holds;
    - ``if (cond) revert ...`` — an ``IF`` node whose then-branch (its
      first successor, by parser construction) aborts, so execution
      continues only when ``cond`` does *not* hold.
    """
    checks: list[_GuardRequirement] = []
    for node in view.nodes:
        owner = owner_function(node, function)
        for index, op in enumerate(node.ir_operations):
            invert = False
            if (
                isinstance(op, SolidityCall)
                and getattr(op.function, "name", "") in ("require", "assert")
                and op.arguments
            ):
                candidates = _condition_requirements(op.arguments[0], owner)
            elif isinstance(op, Condition) and node.kind is NodeKind.IF:
                successors = view.succ[id(node)]
                if not successors or not _is_revert_node(successors[0]):
                    continue
                candidates = _condition_requirements(op.value, owner)
                invert = True
            else:
                continue
            for var, mode, value in candidates:
                checks.append(
                    _GuardRequirement(
                        var=var,
                        mode=_invert_mode(mode) if invert else mode,
                        value=value,
                        node=node,
                        op_index=index,
                    )
                )
    return checks


def _view_state_writes(
    view: _GraphView,
) -> dict[int, list[tuple[CFGNode, int, StateVariable, Any]]]:
    """State writes per variable: (node, op index, var, rvalue-or-None)."""
    writes: dict[int, list[tuple[CFGNode, int, StateVariable, Any]]] = {}
    for node in view.nodes:
        for index, op in enumerate(node.ir_operations):
            var = _written_state_var(op)
            if var is None:
                continue
            rvalue = op.rvalue if isinstance(op, Assignment) else None
            writes.setdefault(id(var), []).append((node, index, var, rvalue))
    return writes


def _dominators(view: _GraphView) -> dict[int, set[int]]:
    """Dominator sets (reflexive) over a graph view, keyed by ``id(node)``.

    Standard iterative dataflow; nodes without predecessors (the composed
    entry, plus any unreachable segments) are their own only dominator.
    """
    universe = {id(node) for node in view.nodes}
    dom: dict[int, set[int]] = {node_id: set(universe) for node_id in universe}
    for node in view.nodes:
        if not view.pred[id(node)]:
            dom[id(node)] = {id(node)}
    changed = True
    while changed:
        changed = False
        for node in view.nodes:
            preds = view.pred[id(node)]
            if not preds:
                continue
            current = {id(node)} | set.intersection(*(dom[id(p)] for p in preds))
            if current != dom[id(node)]:
                dom[id(node)] = current
                changed = True
    return dom


def _position_before(
    dom: dict[int, set[int]],
    a_node: CFGNode,
    a_index: int,
    b_node: CFGNode,
    b_index: int,
) -> bool:
    """True when position ``a`` strictly precedes position ``b`` on all paths."""
    if a_node is b_node:
        return a_index < b_index
    return id(a_node) in dom[id(b_node)]


def _satisfies_lock(requirement: _GuardRequirement, rvalue: Any) -> bool:
    """True when writing ``rvalue`` makes the guard trip on re-entry."""
    if rvalue is None:
        return False
    if requirement.mode == "ne":
        return _same_value(rvalue, requirement.value)
    if requirement.mode == "eq":
        return _provably_different(rvalue, requirement.value)
    literal = _literal_int(rvalue)
    if requirement.mode == "falsey":
        return literal is not None and literal != 0
    if requirement.mode == "truthy":
        return literal == 0
    return False


def _satisfies_unlock(requirement: _GuardRequirement, rvalue: Any) -> bool:
    """True when writing ``rvalue`` restores the value the guard checks for."""
    if rvalue is None:
        return False
    if requirement.mode == "ne":
        return _provably_different(rvalue, requirement.value)
    if requirement.mode == "eq":
        return _same_value(rvalue, requirement.value)
    literal = _literal_int(rvalue)
    if requirement.mode == "falsey":
        return literal == 0
    if requirement.mode == "truthy":
        return literal is not None and literal != 0
    return False


def _unlock_reachable(
    view: _GraphView,
    requirement: _GuardRequirement,
    call_node: CFGNode,
    call_index: int,
) -> bool:
    """True when an unlock-valued write to the guard var may run after the call."""
    visited: set[int] = set()
    stack: list[CFGNode] = [call_node]
    while stack:
        node = stack.pop()
        if id(node) in visited:
            continue
        visited.add(id(node))
        start = call_index + 1 if node is call_node else 0
        for index in range(start, len(node.ir_operations)):
            op = node.ir_operations[index]
            if _written_state_var(op) is not requirement.var:
                continue
            rvalue = op.rvalue if isinstance(op, Assignment) else None
            if _satisfies_unlock(requirement, rvalue):
                return True
        stack.extend(view.succ[id(node)])
    return False


def _interaction_guards(
    view: _GraphView,
    dom: dict[int, set[int]],
    checks: list[_GuardRequirement],
    writes: dict[int, list[tuple[CFGNode, int, StateVariable, Any]]],
    call_node: CFGNode,
    call_index: int,
) -> list[StateVariable]:
    """State variables acting as a reentrancy guard for one interaction.

    A variable qualifies when (a) a guard check on it strictly precedes the
    interaction on every path (dominance over the spliced view), (b) a lock
    write — a value inconsistent with the check, so re-entry reverts — runs
    after the check and before the interaction on every path, and (c) an
    unlock write restoring the checked value may run after the interaction.
    """
    guards: list[StateVariable] = []
    for requirement in checks:
        if any(v is requirement.var for v in guards):
            continue
        if not _position_before(
            dom, requirement.node, requirement.op_index, call_node, call_index
        ):
            continue
        locked = False
        for wnode, windex, _var, rvalue in writes.get(id(requirement.var), ()):
            if not _position_before(
                dom, requirement.node, requirement.op_index, wnode, windex
            ):
                continue
            if not _position_before(dom, wnode, windex, call_node, call_index):
                continue
            if _satisfies_lock(requirement, rvalue):
                locked = True
                break
        if not locked:
            continue
        if not _unlock_reachable(view, requirement, call_node, call_index):
            continue
        guards.append(requirement.var)
    return guards


def _apply_guard_suppression(
    function: FunctionLike,
    view: _GraphView,
    own_contexts: list[CallContext],
    merged: dict[int, CallContext],
    merged_records: dict[int, list[_InteractionRecord]],
    merged_sites: dict[int, list[tuple[CFGNode, int]]],
    order: list[int],
) -> None:
    """Recognize mutex-guarded interactions and suppress their findings.

    A guarded interaction cannot be re-entered, so its writes/events after
    the call are cleared.  Guard variables recognized anywhere in the
    function are mutex machinery: their writes are also removed from the
    writes-after classification of the function's *other* interactions.

    For interactions reached through inlined internal calls, every
    checkpoint along the inlining path (the interaction's own position and
    each call site that lifted it) is evaluated: a mutex recognized at any
    level of the path protects the interaction.
    """
    if not own_contexts and not order:
        return
    dom = _dominators(view)
    checks = _view_guard_checks(view, function)
    writes = _view_state_writes(view)

    machinery_ids: set[int] = set()

    def note(variables: list[StateVariable]) -> None:
        for var in variables:
            machinery_ids.add(id(var))

    for context in own_contexts:
        context.guarded_by = _interaction_guards(
            view, dom, checks, writes, context.node, context.op_index
        )
        note(context.guarded_by)

    view_cache: dict[int, tuple[dict[int, set[int]], list[_GuardRequirement], Any]] = {}

    def _guards_at(
        cp_view: _GraphView, owner: FunctionLike, cp_node: CFGNode, cp_index: int
    ) -> list[StateVariable]:
        cached = view_cache.get(id(cp_view))
        if cached is None:
            cached = (
                _dominators(cp_view),
                _view_guard_checks(cp_view, owner),
                _view_state_writes(cp_view),
            )
            view_cache[id(cp_view)] = cached
        cdom, cchecks, cwrites = cached
        return _interaction_guards(
            cp_view, cdom, cchecks, cwrites, cp_node, cp_index
        )

    for key in order:
        context = merged[key]
        in_path: list[StateVariable] = []
        for record in merged_records[key]:
            for cp_view, cp_owner, cp_node, cp_index in record.checkpoints:
                for var in _guards_at(cp_view, cp_owner, cp_node, cp_index):
                    if not any(v is var for v in in_path):
                        in_path.append(var)
        per_site: list[StateVariable] = []
        all_sites_guarded = bool(merged_sites[key])
        for site_node, site_index in merged_sites[key]:
            site_guards = _interaction_guards(
                view, dom, checks, writes, site_node, site_index
            )
            if not site_guards:
                all_sites_guarded = False
            for var in site_guards:
                if not any(v is var for v in per_site):
                    per_site.append(var)
        if in_path:
            context.guarded_by = in_path + [
                v for v in per_site if not any(g is v for g in in_path)
            ]
        elif all_sites_guarded:
            context.guarded_by = per_site
        else:
            context.guarded_by = []
        note(in_path)
        note(per_site)

    for context in list(own_contexts) + [merged[key] for key in order]:
        if context.guarded_by:
            if context.writes_after or context.events_after:
                logger.debug(
                    "reentrancy: %s interaction is behind reentrancy guard "
                    "variable(s) %s; suppressing %d write(s) and %d event(s) "
                    "after the call",
                    context.function.canonical_name,
                    [var.name for var in context.guarded_by],
                    len(context.writes_after),
                    len(context.events_after),
                )
            context.writes_after = []
            context.events_after = []
        elif machinery_ids:
            context.writes_after = [
                (var, node)
                for var, node in context.writes_after
                if id(var) not in machinery_ids
            ]


def function_call_contexts(
    function: FunctionLike,
    safe_state_vars: Optional[set[int]] = None,
    contract: Any = None,
) -> list[CallContext]:
    """All re-enterable interactions of a function, with flow facts.

    Interactions are collected from the function body, from applied
    modifier bodies (spliced at ``_``), and — up to ``_MAX_INLINE_DEPTH``
    levels deep — from called internal helpers (plain ``InternalCall`` ops,
    resolved to the most-derived override within ``contract``, and
    base-qualified static calls like ``Base.f(args)``, which compile to
    internal jumps).  Helper facts at a call site are may-unions; per
    interaction they are merged over every call site reaching it.
    ``safe_state_vars`` holds ``id()``s of NatSpec-tagged state variables
    excluded from the writes-after classification (spec §11.3).
    Interactions protected by a recognized reentrancy guard (mutex) have
    their writes/events after the call suppressed and carry the guard
    variables in ``CallContext.guarded_by`` (module docstring).
    """
    safe = frozenset(safe_state_vars or ())
    view = _build_graph_view(function)
    sites = _inline_sites(function, view, contract=contract)
    contexts: list[CallContext] = []

    # 1. interactions in the function body and its modifier bodies.
    own_contexts: list[CallContext] = []
    for node in view.nodes:
        owner = owner_function(node, function)
        for index, op in enumerate(node.ir_operations):
            classified = _classify_interaction(op)
            if classified is None:
                continue
            sends_eth, gas_bounded = classified
            writes, events = _collect_after(view, sites, node, index, safe)
            own_contexts.append(
                CallContext(
                    function=function,
                    owner=owner,
                    node=node,
                    op=op,
                    op_index=index,
                    sends_eth=sends_eth,
                    gas_bounded=gas_bounded,
                    reads_before=_collect_reads_before(
                        view, sites, node, index, op, owner
                    ),
                    writes_after=writes,
                    events_after=events,
                )
            )
    contexts.extend(own_contexts)

    # 2. interactions inside internal helpers (bounded-depth), merged per
    #    interaction op over every call site reaching it.
    merged: dict[int, CallContext] = {}
    merged_records: dict[int, list[_InteractionRecord]] = {}
    merged_sites: dict[int, list[tuple[CFGNode, int]]] = {}
    order: list[int] = []
    for node in view.nodes:
        owner = owner_function(node, function)
        for index, op in enumerate(node.ir_operations):
            helper = sites.get((id(node), index))
            if helper is None or not helper.records:
                continue
            site_reads = _collect_reads_before(view, sites, node, index, op, owner)
            site_writes, site_events = _collect_after(view, sites, node, index, safe)
            for record in helper.records:
                key = id(record.op)
                context = merged.get(key)
                if context is None:
                    context = CallContext(
                        function=function,
                        owner=record.owner,
                        node=record.node,
                        op=record.op,
                        op_index=record.op_index,
                        sends_eth=record.sends_eth,
                        gas_bounded=record.gas_bounded,
                    )
                    merged[key] = context
                    merged_records[key] = []
                    merged_sites[key] = []
                    order.append(key)
                merged_records[key].append(record)
                if (node, index) not in merged_sites[key]:
                    merged_sites[key].append((node, index))
                for var in record.reads_before:
                    if not context.read_before(var):
                        context.reads_before.append(var)
                for var in site_reads:
                    if not context.read_before(var):
                        context.reads_before.append(var)
                for var, write_node in record.writes_after:
                    if id(var) in safe:
                        continue
                    if not any(v is var for v, _n in context.writes_after):
                        context.writes_after.append((var, write_node))
                for var, write_node in site_writes:
                    if not any(v is var for v, _n in context.writes_after):
                        context.writes_after.append((var, write_node))
                for event_op, event_node in record.events_after:
                    if not any(e is event_op for e, _n in context.events_after):
                        context.events_after.append((event_op, event_node))
                for event_op, event_node in site_events:
                    if not any(e is event_op for e, _n in context.events_after):
                        context.events_after.append((event_op, event_node))
    contexts.extend(merged[key] for key in order)
    _apply_guard_suppression(
        function, view, own_contexts, merged, merged_records, merged_sites, order
    )
    return contexts


def sources_statically_trusted(expanded: list[Any]) -> bool:
    """True when *every* source leaf is statically trusted.

    ``address(this)`` and literal constant addresses cannot be swapped out
    by an attacker.  Every leaf of the expansion must be trusted: a single
    parameter, state variable or ``msg.sender`` anywhere in the destination
    expression (even just feeding an index) makes it untrusted.
    """
    if not expanded:
        return False
    for var in expanded:
        if isinstance(var, SolidityVariable) and var.name == "this":
            continue
        if isinstance(var, Constant):
            continue
        return False
    return True


def destination_is_trusted(context: CallContext) -> bool:
    """True when the call destination is statically trusted."""
    destination = getattr(context.op, "destination", None)
    if destination is None:
        return False
    return sources_statically_trusted(
        expand_terminal_sources([destination], context.owner)
    )


def gating_writes(context: CallContext) -> list[tuple[StateVariable, CFGNode]]:
    """Writes after the interaction to state vars read on the path to it."""
    return [
        (var, node) for var, node in context.writes_after if context.read_before(var)
    ]


def non_gating_writes(context: CallContext) -> list[tuple[StateVariable, CFGNode]]:
    """Writes after the interaction to state vars not read before it."""
    return [
        (var, node)
        for var, node in context.writes_after
        if not context.read_before(var)
    ]


def natspec_tagged_state_variables(
    compilation_unit: Any,
    tag: str = "custom:security",
    value: str = "non-reentrant",
) -> set[int]:
    """``id()``s of state variables whose doc comment carries ``@tag value``.

    The tag marks externally-called variables considered safe; reentrancy
    detectors exclude them from the "state variables written after call"
    classification (spec/architecture.md §11.3).
    """
    sources: dict[str, str] = {}
    for info in compilation_unit.compilation.source_units.values():
        sources.setdefault(info.filename.absolute, info.source)
    tagged: set[int] = set()
    for var in compilation_unit.state_variables:
        mapping = var.source_mapping
        if mapping is None or mapping.filename is None:
            continue
        source = sources.get(mapping.filename.absolute)
        if source is None:
            continue
        if has_tag(docstring_above(source, mapping.start), tag, value):
            tagged.add(id(var))
    return tagged


def iter_analyzable_functions(compilation_unit: Any) -> Iterator[FunctionLike]:
    """Implemented, non-constructor functions of derived contracts."""
    for contract in compilation_unit.contracts_derived:
        for function in contract.available_functions_from_inheritances():
            if function.is_constructor or not function.is_implemented:
                continue
            yield function


def iter_analyzable_functions_with_contract(
    compilation_unit: Any,
) -> Iterator[tuple[Any, FunctionLike]]:
    """Like :func:`iter_analyzable_functions`, but also yields the derived
    contract under analysis — the context needed to resolve virtual
    internal calls to the most-derived override."""
    for contract in compilation_unit.contracts_derived:
        for function in contract.available_functions_from_inheritances():
            if function.is_constructor or not function.is_implemented:
                continue
            yield contract, function
