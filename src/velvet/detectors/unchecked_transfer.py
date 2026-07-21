"""`unchecked-transfer` detector (spec/detectors-catalog.md §4.3 —
normative).

Flags ERC-20 ``transfer``/``transferFrom`` calls whose boolean return value
is ignored: many tokens signal failure by returning ``false`` instead of
reverting, so ignoring the result makes failed transfers look successful
(SWC-104).

A result is considered handled when it flows into a condition, a
``require``/``assert`` guard, or is returned to the caller (forwarding the
status is legitimate handling).  Calls to tokens whose function returns
nothing produce no boolean and are not reported.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_b_utils import terminal_consumers
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
    Operation,
    Return,
    SolidityCall,
)

_TRANSFER_NAMES = ("transfer", "transferFrom")
_GUARD_BUILTINS = ("require", "assert")


class UncheckedTransfer(Detector):
    """Detect ignored transfer/transferFrom return values."""

    RULE = "unchecked-transfer"
    TITLE = "Unchecked ERC-20 transfer return value"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#unchecked-transfer",
        title="Unchecked ERC-20 transfer return value",
        description=(
            "transfer/transferFrom calls whose boolean return value is "
            "ignored; tokens that return false instead of reverting make "
            "failed transfers look successful (SWC-104)."
        ),
        exploit_scenario=(
            "unstake(token, amount) decreases the stake and calls "
            "token.transfer(msg.sender, amount) without checking the "
            "result; a silently failing transfer leaves the user's stake "
            "gone without receiving tokens."
        ),
        recommendation=(
            "Use a safe-transfer library (e.g. SafeERC20.safeTransfer) or "
            "explicitly check the return value (and handle tokens with no "
            "return value)."
        ),
    )

    @staticmethod
    def _is_handled(consumers: list[Operation]) -> bool:
        """The boolean result is validated or forwarded to the caller."""
        for op in consumers:
            if isinstance(op, (Condition, Return)):
                return True
            if isinstance(op, SolidityCall) and op.function.name in _GUARD_BUILTINS:
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
                for node in function.all_nodes:
                    for op in node.ir_operations:
                        if not (
                            isinstance(op, HighLevelCall)
                            and op.function_name in _TRANSFER_NAMES
                            and op.lvalue is not None
                        ):
                            continue
                        consumers = terminal_consumers(function, [op.lvalue])
                        if self._is_handled(consumers):
                            continue
                        results.append(
                            self.finding(
                                [
                                    node,
                                    " ignores the return value of "
                                    f"{op.function_name} in ",
                                    function,
                                ]
                            )
                        )
        return results
