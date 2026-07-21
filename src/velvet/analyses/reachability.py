"""Call-graph reachability and CFG loop membership (spec §7.4, §5).

Original clean-room implementation.
"""

from __future__ import annotations


from velvet.core.function import Function, FunctionLike
from velvet.analyses.read_write import internal_call_targets


def internal_calls_reachable(function: FunctionLike) -> list[FunctionLike]:
    """Transitive internal call targets of a function (cycle-safe).

    Traverses internal calls, library calls, applied modifiers and
    resolvable internal dynamic calls (see
    :func:`velvet.analyses.read_write.internal_call_targets`).  Because an
    internal call to a virtual function dispatches to the most-derived
    override at runtime, the override graph is also traversed downward:
    when a target is reached, the functions overriding it are reachable
    too (the base implementation itself is *not* reachable from overrides
    unless ``super``-called, so the ``overrides`` direction is not
    followed).
    """
    result: list[FunctionLike] = []
    stack = list(internal_call_targets(function))
    while stack:
        target = stack.pop()
        if any(t is target for t in result):
            continue
        result.append(target)
        stack.extend(internal_call_targets(target))
        # Virtual dispatch: a call to a base/virtual implementation may
        # execute any of its overrides instead.
        stack.extend(getattr(target, "overridden_by", None) or [])
    return result


def is_reachable_from(entry: FunctionLike, target: FunctionLike) -> bool:
    """True when ``target`` is ``entry`` or reachable through internal calls."""
    if entry is target:
        return True
    return any(t is target for t in internal_calls_reachable(entry))


def entry_points_reaching(function: FunctionLike) -> list[Function]:
    """External/public functions of the same contract that can reach
    ``function`` (spec §7.4 entry-point sets)."""
    contract = function.contract_declarer or function.contract
    if contract is None:
        return []
    result: list[Function] = []
    for entry in contract.functions_entry_points:
        if is_reachable_from(entry, function):
            result.append(entry)
    return result


def compute_loop_membership(function: FunctionLike) -> None:
    """Mark each node with ``_inside_loop`` (natural-loop membership).

    The parser tags nodes built inside a loop (``_inside_loop_parse``);
    those marks are authoritative because they also cover nodes a
    dominator-based natural loop cannot see (``return``/``throw`` inside
    the body never reaches the back edge, and a do-while body is not
    dominated by its header).  When no parse marks exist (synthesized
    CFGs), fall back to natural loops: per back edge ``n -> h`` where
    ``h`` dominates ``n``, the body is ``h`` plus every node that can
    reach ``n`` without passing through ``h``.
    """
    nodes = function.nodes
    if any(getattr(node, "_inside_loop_parse", False) for node in nodes):
        for node in nodes:
            node._inside_loop = bool(  # type: ignore[attr-defined]
                getattr(node, "_inside_loop_parse", False)
            )
        return
    for node in nodes:
        node._inside_loop = False  # type: ignore[attr-defined]
    if not nodes:
        return
    # dominator sets (simple dataflow; functions are small)
    index = {id(n): i for i, n in enumerate(nodes)}
    reachable = [n for n in nodes if n.is_reachable]
    dom: dict[int, set[int]] = {id(n): set(range(len(nodes))) for n in reachable}
    if reachable:
        dom[id(reachable[0])] = {index[id(reachable[0])]}
    changed = True
    while changed:
        changed = False
        for node in reachable[1:]:
            preds = [p for p in node.predecessors if p.is_reachable]
            if not preds:
                continue
            new = {index[id(node)]}
            inter: set[int] | None = None
            for p in preds:
                pset = dom[id(p)]
                inter = pset if inter is None else inter & pset
            new |= inter or set()
            if new != dom[id(node)]:
                dom[id(node)] = new
                changed = True

    for node in reachable:
        for succ in node.successors:
            if not succ.is_reachable:
                continue
            # back edge: successor dominates node
            if index[id(succ)] in dom[id(node)]:
                body = {id(succ)}
                stack = [node]
                while stack:
                    current = stack.pop()
                    if id(current) in body:
                        continue
                    body.add(id(current))
                    stack.extend(current.predecessors)
                for member_id in body:
                    for candidate in nodes:
                        if id(candidate) == member_id:
                            candidate._inside_loop = True  # type: ignore[attr-defined]
