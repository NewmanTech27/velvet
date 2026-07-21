"""`weak-prng` detector (spec/detectors-catalog.md §7.13 — normative).

Flags pseudo-randomness derived from block variables — ``block.timestamp``,
``blockhash(...)``, ``block.number``, ``block.difficulty``/``prevrandao``,
``block.coinbase``, ``gasleft`` (legacy ``now``) — typically via a modulo.
Miners/validators can influence these values and contracts can predict
them, breaking lotteries, games, and random assignments (SWC-120).

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Iterable

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
from velvet.ir.operations import Binary, Operation, SolidityCall

#: Block environment variables usable as (weak) randomness sources.
WEAK_SOURCES = (
    "block.timestamp",
    "block.number",
    "block.difficulty",
    "block.prevrandao",
    "block.coinbase",
    "gasleft",
    "now",
)

#: Solidity builtins producing weak randomness-relevant values.
_WEAK_BUILTINS = ("blockhash",)

#: Modulo builtins (SolidityCall form of the % idiom).
_MODULO_BUILTINS = ("addmod", "mulmod")


class WeakPrng(Detector):
    """Detect randomness derived from block variables."""

    RULE = "weak-prng"
    TITLE = "Weak pseudo-randomness from block variables"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#weak-prng",
        title="Weak pseudo-randomness from block variables",
        description=(
            "Randomness derived from block variables (block.timestamp, "
            "blockhash, block.number, block.difficulty/prevrandao, "
            "block.coinbase, gasleft) can be influenced by validators or "
            "predicted by contracts (SWC-120)."
        ),
        exploit_scenario=(
            "A coin flip computes (uint256(blockhash(block.number - 1)) + "
            "block.timestamp) % 2; an attacker contract computes the same "
            "value and only plays winning flips."
        ),
        recommendation=(
            "Use a commit-reveal scheme or a verifiable randomness oracle "
            "(Chainlink VRF, Gelato VRF); never use block variables as "
            "randomness."
        ),
    )

    @staticmethod
    def _uses_weak_source(
        function: FunctionLike,
        seeds: Iterable[Any],
        defs: dict[int, Operation],
    ) -> bool:
        variables, ops = def_chain(function, seeds, defs)
        for var in variables:
            if isinstance(var, SolidityVariable) and var.name in WEAK_SOURCES:
                return True
        for op in ops:
            if isinstance(op, SolidityCall) and op.function.name in _WEAK_BUILTINS:
                return True
        return False

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        seen_functions: set[int] = set()
        for contract in self.compilation_unit.contracts_derived:
            functions = list(contract.available_functions_from_inheritances())
            functions += list(contract.all_modifiers())
            for function in functions:
                if id(function) in seen_functions:
                    continue
                seen_functions.add(id(function))
                defs = defining_ops(function)
                for node in function.all_nodes:
                    flagged = False
                    for op in node.ir_operations:
                        if isinstance(op, Binary) and op.operator == "%":
                            if self._uses_weak_source(function, [op.left, op.right], defs):
                                flagged = True
                        elif (
                            isinstance(op, SolidityCall)
                            and op.function.name in _MODULO_BUILTINS
                        ):
                            if self._uses_weak_source(function, op.arguments, defs):
                                flagged = True
                        if flagged:
                            break
                    if flagged:
                        results.append(
                            self.finding(
                                [
                                    node,
                                    " derives pseudo-randomness from block "
                                    "variables in ",
                                    function,
                                ]
                            )
                        )
        return results
