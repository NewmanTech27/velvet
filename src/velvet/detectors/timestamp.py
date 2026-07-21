"""`timestamp` detector (spec/detectors-catalog.md §7.39 — normative).

Flags dangerous reliance on ``block.timestamp`` (legacy ``now``) in program
logic (SWC-116): the timestamp used in comparisons or arithmetic that gates
state-changing logic or value flows — strict equality, modulo-based
randomness, short-window ordering assumptions, and ordering/deadline
comparisons — including conditions that consume a boolean derived from such
a comparison (e.g. a ``require``/``if`` on a validity flag computed from
``block.timestamp``, possibly returned by an internal helper).

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.core.function import FunctionLike
from velvet.core.variables import SolidityVariable
from velvet.detectors._batch_b_utils import def_chain, defining_ops
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import (
    Binary,
    Condition,
    InternalCall,
    Operation,
    Return,
    SolidityCall,
    Unpack,
)
from velvet.ir.variables import TupleVariable

_TIMESTAMP_VARIABLES = ("block.timestamp", "now")

#: Comparisons (and the modulo form) whose operands must not be derived
#: from the timestamp.
_COMPARISON_OPERATORS = ("==", "!=", "<", ">", "<=", ">=", "%")
#: Logical combinators that propagate a timestamp-derived boolean into a
#: gating condition.
_LOGICAL_OPERATORS = ("&&", "||")


def _has_timestamp(variables: list[Any]) -> bool:
    return any(
        isinstance(var, SolidityVariable) and var.name in _TIMESTAMP_VARIABLES
        for var in variables
    )


class Timestamp(Detector):
    """Detect dangerous reliance on block.timestamp."""

    RULE = "timestamp"
    TITLE = "Dangerous usage of block.timestamp"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#timestamp",
        title="Dangerous usage of block.timestamp",
        description=(
            "block.timestamp can be nudged by validators within a small "
            "window; using it in comparisons or arithmetic that gates "
            "state-changing logic or value flows is exploitable (SWC-116)."
        ),
        exploit_scenario=(
            "claimWindow() pays out when block.timestamp % 60 == 0; a "
            "validator nudges the timestamp of its own block into the "
            "winning window."
        ),
        recommendation=(
            "Avoid tight timestamp dependencies; tolerate ~15s drift; never "
            "use timestamps as randomness."
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._defs_cache: dict[int, dict[int, Operation]] = {}
        self._comparison_cache: dict[int, bool] = {}
        self._tainted_returns_cache: dict[int, frozenset[int]] = {}
        self._tainted_returns_visiting: set[int] = set()

    # --------------------------------------------------------- def chains
    def _defs(self, function: FunctionLike) -> dict[int, Operation]:
        cached = self._defs_cache.get(id(function))
        if cached is None:
            cached = defining_ops(function)
            self._defs_cache[id(function)] = cached
        return cached

    def _reads_timestamp(self, function: FunctionLike, seeds: list[Any]) -> bool:
        variables, _ = def_chain(function, seeds, self._defs(function))
        return _has_timestamp(variables)

    def _is_timestamp_comparison(self, function: FunctionLike, op: Operation) -> bool:
        """True for a comparison/modulo op whose operands read the timestamp."""
        if not (isinstance(op, Binary) and op.operator in _COMPARISON_OPERATORS):
            return False
        cached = self._comparison_cache.get(id(op))
        if cached is None:
            cached = self._reads_timestamp(function, [op.left, op.right])
            self._comparison_cache[id(op)] = cached
        return cached

    # --------------------------------------------------- taint propagation
    def _tainted_return_indices(self, function: FunctionLike) -> frozenset[int]:
        """Indices of the returned values of ``function`` that are derived
        from a timestamp comparison (directly or via an internal helper)."""
        cached = self._tainted_returns_cache.get(id(function))
        if cached is not None:
            return cached
        if id(function) in self._tainted_returns_visiting:
            return frozenset()  # recursion guard; memoized on unwind
        self._tainted_returns_visiting.add(id(function))
        try:
            tainted: set[int] = set()
            for node in function.all_nodes:
                for op in node.ir_operations:
                    if not (isinstance(op, Return) and op.values):
                        continue
                    for index, value in enumerate(op.values):
                        if self._chain_has_taint(function, [value]):
                            tainted.add(index)
            result = frozenset(tainted)
            self._tainted_returns_cache[id(function)] = result
            return result
        finally:
            self._tainted_returns_visiting.discard(id(function))

    def _chain_has_taint(self, function: FunctionLike, seeds: list[Any]) -> bool:
        """True when the def-chain of ``seeds`` contains a timestamp
        comparison or a timestamp-derived value returned by an internal
        call (tracked per tuple slot through ``Unpack``)."""
        defs = self._defs(function)
        _, ops = def_chain(function, seeds, defs)
        for chain_op in ops:
            if self._is_timestamp_comparison(function, chain_op):
                return True
            if isinstance(chain_op, Unpack):
                tuple_def = defs.get(id(chain_op.tuple_variable))
                if (
                    isinstance(tuple_def, InternalCall)
                    and tuple_def.function is not None
                    and chain_op.index
                    in self._tainted_return_indices(tuple_def.function)
                ):
                    return True
            elif (
                isinstance(chain_op, InternalCall)
                and chain_op.function is not None
                and not isinstance(chain_op.lvalue, TupleVariable)
                and self._tainted_return_indices(chain_op.function)
            ):
                return True
        return False

    # -------------------------------------------------------------- driver
    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        # All functions/modifiers of every contract (not only most-derived
        # ones) so private helpers of base contracts are covered too.
        for function in self.compilation_unit.functions_and_modifiers:
            for node in function.all_nodes:
                flagged = False
                for op in node.ir_operations:
                    if self._is_timestamp_comparison(function, op):
                        flagged = True
                        break
                    if (
                        isinstance(op, Binary)
                        and op.operator in _LOGICAL_OPERATORS
                        and self._chain_has_taint(function, [op.left, op.right])
                    ):
                        flagged = True
                        break
                    if isinstance(op, Condition) and self._chain_has_taint(
                        function, [op.value]
                    ):
                        flagged = True
                        break
                    if (
                        isinstance(op, SolidityCall)
                        and op.function.name in ("require", "assert")
                        and self._chain_has_taint(function, list(op.arguments))
                    ):
                        flagged = True
                        break
                if flagged:
                    results.append(
                        self.finding(
                            [
                                node,
                                " relies on block.timestamp in a "
                                "comparison or condition in ",
                                function,
                            ]
                        )
                    )
        return results
