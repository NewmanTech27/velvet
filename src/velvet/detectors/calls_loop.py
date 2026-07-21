"""`calls-loop` detector (spec/detectors-catalog.md §7.35 — normative).

Flags external calls executed inside a loop body: if any callee reverts
(or runs out of gas) the whole transaction reverts, permanently locking
the function — a griefing/DoS vector when the iterated collection is
attacker-influenced — and unbounded loops risk the block gas limit.

A loop body "contains" a call both lexically and through the internal
calls the loop makes: an external call inside an internal function that
is (transitively) invoked from within a loop body runs once per
iteration, so it is reported as well, with the loop entry point noted.
Virtual dispatch is honored by also following every overriding
implementation of an internal call target.

Library calls are excluded (they execute in-contract); so are qualified
``ContractName.f(...)`` calls (``ERC20Upgradeable.balanceOf(...)``,
``ModuleInternal._f(...)``) which solc only accepts for base contracts
— internal calls in disguise, and as such also followed transitively.
Every other call shape reaching external code is reported: high-level
contract calls, low-level ``call``/``delegatecall``/``staticcall``/
``callcode``, and the ``transfer``/``send`` Ether-forwarding forms.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Iterator

from velvet.core.contract import Contract
from velvet.core.function import FunctionLike
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import (
    HighLevelCall,
    InternalCall,
    LibraryCall,
    LowLevelCall,
    Send,
    Transfer,
)

_EXTERNAL_CALL_OPS = (HighLevelCall, LowLevelCall, Send, Transfer)


class CallsLoop(Detector):
    """Detect external calls inside loop bodies."""

    RULE = "calls-loop"
    TITLE = "External calls inside a loop"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#calls-loop",
        title="External calls inside a loop",
        description=(
            "A loop body contains an external call (call, transfer, send, "
            "or a call to another contract) — directly or through an "
            "internal function the loop invokes; one reverting or "
            "gas-hungry callee reverts the whole transaction and "
            "permanently locks the function."
        ),
        exploit_scenario=(
            "distribute() loops over shareholders calling "
            "payable(shareholders[i]).transfer(...); a single shareholder "
            "contract whose fallback reverts bricks all payouts."
        ),
        recommendation=(
            "Use a pull-over-push pattern (let recipients withdraw), "
            "and/or bound loop iterations with batching."
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._callee_cache: dict[int, list[FunctionLike]] = {}

    # ------------------------------------------------------ call graph
    def _all_functions(self) -> list[FunctionLike]:
        # All functions/modifiers of every contract (not only most-derived
        # ones) so private helpers of base contracts are covered too.
        return list(self.compilation_unit.functions_and_modifiers)

    @staticmethod
    def _overriders_of(function: FunctionLike) -> list[FunctionLike]:
        """Every implementation overriding ``function`` (virtual dispatch)."""
        return list(getattr(function, "overridden_by", []) or [])

    @staticmethod
    def _internal_call_targets(node: Any) -> Iterator[FunctionLike]:
        """Internal-call targets of one node.

        Besides plain ``InternalCall`` ops, a *qualified* call whose
        destination is the contract type itself (``ModuleInternal._f(...)``
        / ``Base.f(...)``) dispatches internally (solc only accepts that
        form for base contracts; libraries become ``LibraryCall``), so it
        is an internal edge even though the IR shapes it as a
        ``HighLevelCall``.
        """
        for op in node.ir_operations:
            if isinstance(op, InternalCall) and op.function is not None:
                yield op.function
            elif (
                isinstance(op, HighLevelCall)
                and isinstance(op.destination, Contract)
                and op.function is not None
            ):
                yield op.function

    def _internal_callees(self, function: FunctionLike) -> list[FunctionLike]:
        """Internal-call targets of ``function`` (bodies only, no overrides)."""
        cached = self._callee_cache.get(id(function))
        if cached is not None:
            return cached
        callees: list[FunctionLike] = []
        seen: set[int] = set()
        for node in function.all_nodes:
            for target in self._internal_call_targets(node):
                if id(target) not in seen:
                    seen.add(id(target))
                    callees.append(target)
        # Modifier bodies execute as part of the function.
        for modifier in getattr(function, "modifiers", []) or []:
            if isinstance(modifier, FunctionLike) and id(modifier) not in seen:
                seen.add(id(modifier))
                callees.append(modifier)
        self._callee_cache[id(function)] = callees
        return callees

    # ------------------------------------------------------ loop reachability
    def _loop_reachable(self) -> dict[int, FunctionLike]:
        """Map: function reachable from a loop body -> one looping entry."""
        entry: dict[int, FunctionLike] = {}
        stack: list[tuple[FunctionLike, FunctionLike]] = []
        for function in self._all_functions():
            for node in function.nodes:
                if not node.is_inside_loop:
                    continue
                for target in self._internal_call_targets(node):
                    stack.append((target, function))
        while stack:
            callee, source = stack.pop()
            if id(callee) in entry:
                continue
            entry[id(callee)] = source
            # Virtual dispatch: an internal call may run an override.
            for overrider in self._overriders_of(callee):
                stack.append((overrider, source))
            for nxt in self._internal_callees(callee):
                stack.append((nxt, source))
        return entry

    # ------------------------------------------------------ helpers
    @staticmethod
    def _is_qualified_internal_call(op: Any) -> bool:
        """True for qualified ``ContractName.f(...)`` calls — these dispatch
        internally, not to another contract (see _internal_call_targets)."""
        return isinstance(op, HighLevelCall) and isinstance(op.destination, Contract)

    def _external_call_ops(self, node: Any) -> Iterator[Any]:
        for op in node.ir_operations:
            if isinstance(op, LibraryCall) or not isinstance(op, _EXTERNAL_CALL_OPS):
                continue
            if self._is_qualified_internal_call(op):
                continue
            yield op

    # -------------------------------------------------------------- driver
    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        loop_reachable = self._loop_reachable()
        reported_sites: set[int] = set()
        for function in self._all_functions():
            entry_source = loop_reachable.get(id(function))
            for node in function.nodes:
                in_loop = node.is_inside_loop
                if not in_loop and entry_source is None:
                    continue
                for op in self._external_call_ops(node):
                    if id(op) in reported_sites:
                        continue
                    reported_sites.add(id(op))
                    if in_loop:
                        message = [
                            node,
                            " performs an external call inside a loop in ",
                            function,
                            "; a reverting callee locks the whole function",
                        ]
                    else:
                        message = [
                            node,
                            " performs an external call in ",
                            function,
                            ", which is called from a loop in ",
                            entry_source,
                            "; a reverting callee locks the whole function",
                        ]
                    results.append(self.finding(message))
        return results
