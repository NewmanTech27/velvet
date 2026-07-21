"""`reentrancy-balance` detector (spec/detectors-catalog.md §1.2 —
normative).

Flags reentrancy leading to outdated balance checks: a balance-like
value (an ERC-20 ``balanceOf(...)``, an ``.balance`` member read, or an
internal balance mapping entry) is snapshotted into a local before an
external call and re-read after the call to enforce a delta check.  A
re-entrant execution inflates/deflates the intermediate balance, so the
post-call invariant is validated against a manipulated balance.

The detector locates re-enterable interactions with the shared
reentrancy core, then requires — in the def-chain of a post-call guard
(``require``/``assert``/``if``) — a balance read *after* the interaction
paired with a snapshot of the *same* balance taken *before* it.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Iterator, Optional

from velvet.core.cfg_node import CFGNode
from velvet.core.function import FunctionLike
from velvet.core.variables import StateVariable
from velvet.detectors._batch_b_utils import def_chain
from velvet.detectors._reentrancy_common import (
    function_call_contexts,
    iter_analyzable_functions,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import (
    Condition,
    HighLevelCall,
    Index,
    Member,
    Operation,
    SolidityCall,
)
from velvet.ir.variables import ReferenceVariable, root_base

_GUARD_BUILTINS = ("require", "assert")
_BALANCE_MARKERS = ("balance", "Balance")


def _balance_target(op: Operation) -> Optional[Any]:
    """The account/token this op reads the balance of, else None.

    The returned key identifies the balance *source*: two reads with an
    identical key snapshot and re-read the same balance.
    """
    if isinstance(op, HighLevelCall) and op.function_name == "balanceOf":
        return ("balanceOf", id(op.destination))
    if isinstance(op, Member) and op.member_name == "balance":
        return ("balance", id(op.base))
    if isinstance(op, Index):
        base = op.base
        if isinstance(base, ReferenceVariable):
            base = root_base(base)
        if isinstance(base, StateVariable) and any(
            marker in (base.name or "") for marker in _BALANCE_MARKERS
        ):
            return ("mapping", id(base))
    return None


def _is_balance_read(op: Operation) -> bool:
    return op.lvalue is not None and _balance_target(op) is not None


def _is_guard(op: Operation) -> bool:
    if isinstance(op, Condition):
        return True
    return (
        isinstance(op, SolidityCall)
        and getattr(op.function, "name", "") in _GUARD_BUILTINS
    )


def _node_closure(start: CFGNode, edges: dict[int, list[CFGNode]]) -> set[int]:
    """``id()``s of nodes reachable from ``start`` (exclusive) via edges."""
    seen: set[int] = set()
    stack = list(edges.get(id(start), []))
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        stack.extend(edges.get(id(node), []))
    return seen


class ReentrancyBalance(Detector):
    """Detect balance snapshots re-checked after a re-enterable call."""

    RULE = "reentrancy-balance"
    TITLE = "Reentrancy leading to outdated balance check"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#reentrancy-balance",
        title="Reentrancy leading to outdated balance check",
        description=(
            "A balance is snapshotted before an external call and "
            "compared again after it; a re-entrant execution manipulates "
            "the intermediate balance, so the post-call delta check is "
            "validated against a stale snapshot."
        ),
        exploit_scenario=(
            "Minter.mint() records before_ = token.balanceOf(this), calls "
            "an untrusted payer, then requires balanceOf(this) - before_ "
            ">= owed; the payer re-enters and inflates the balance so "
            "the check passes without payment."
        ),
        recommendation=(
            "Use pull payments (transferFrom) instead of balance deltas, "
            "or protect the function with a reentrancy guard."
        ),
    )

    # ----------------------------------------------------------- internals
    def _op_positions(
        self, function: FunctionLike
    ) -> dict[int, tuple[CFGNode, int]]:
        """``id(op) -> (node, index)`` over the function's own nodes."""
        positions: dict[int, tuple[CFGNode, int]] = {}
        for node in function.nodes:
            for index, op in enumerate(node.ir_operations):
                positions[id(op)] = (node, index)
        return positions

    def _analyze_function(self, function: FunctionLike) -> Iterator[Finding]:
        if not function.nodes:
            return
        positions = self._op_positions(function)
        succ = {id(n): list(n.successors) for n in function.nodes}
        pred = {id(n): list(n.predecessors) for n in function.nodes}

        for context in function_call_contexts(function):
            # Only interactions hosted by the function body itself: the
            # raw CFG ordering then matches the source ordering.
            if context.owner is not function:
                continue
            before_nodes = _node_closure(context.node, pred)
            after_nodes = _node_closure(context.node, succ) | {id(context.node)}

            def op_before(op: Operation) -> bool:
                position = positions.get(id(op))
                if position is None:
                    return False
                node, index = position
                if id(node) == id(context.node):
                    return index < context.op_index
                return id(node) in before_nodes

            def op_after(op: Operation) -> bool:
                position = positions.get(id(op))
                if position is None:
                    return False
                node, index = position
                if id(node) == id(context.node):
                    return index > context.op_index
                return id(node) in after_nodes

            reported = False
            for node in function.nodes:
                if reported:
                    break
                if id(node) not in after_nodes:
                    continue
                for index, op in enumerate(node.ir_operations):
                    if reported:
                        break
                    if id(node) == id(context.node) and index <= context.op_index:
                        continue
                    if not _is_guard(op):
                        continue
                    _, chain_ops = def_chain(function, op.read)
                    snapshots = [
                        candidate
                        for candidate in chain_ops
                        if _is_balance_read(candidate) and op_before(candidate)
                    ]
                    rereads = [
                        candidate
                        for candidate in chain_ops
                        if _is_balance_read(candidate) and op_after(candidate)
                    ]
                    if not any(
                        _balance_target(old) == _balance_target(new)
                        for old in snapshots
                        for new in rereads
                    ):
                        continue
                    yield self.finding(
                        [
                            context.node,
                            " performs a re-enterable external call in ",
                            function,
                            " between a balance snapshot and the balance "
                            "delta check enforced at ",
                            node,
                            "; re-entry can make the snapshot stale",
                        ]
                    )
                    reported = True

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in iter_analyzable_functions(self.compilation_unit):
            results.extend(self._analyze_function(function))
        return results
