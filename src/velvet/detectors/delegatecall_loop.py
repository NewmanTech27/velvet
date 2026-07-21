"""`delegatecall-loop` detector (spec/detectors-catalog.md §3.2 — normative).

Flags a ``delegatecall`` executed inside a loop within a ``payable``
function.  ``msg.value`` is constant across loop iterations, so each
iteration re-spends the same value; when the delegated code credits
balances by ``msg.value``, deposits are counted multiple times.

When the destination is ``address(this)`` the finding is suppressed if no
function of the contract can read ``msg.value`` (the delegated code path
cannot then re-spend value).  For external destinations the target code is
unknown and is conservatively assumed able to read ``msg.value``.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.contract import Contract
from velvet.core.function import FunctionLike
from velvet.core.variables import SolidityVariable
from velvet.detectors._batch_b_utils import def_chain
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import LowLevelCall

_DELEGATECALL_NAMES = ("delegatecall", "callcode")


class DelegatecallLoop(Detector):
    """Detect delegatecall inside a loop of a payable function."""

    RULE = "delegatecall-loop"
    TITLE = "Delegatecall inside a loop"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#delegatecall-loop",
        title="Delegatecall inside a loop",
        description=(
            "A delegatecall inside a loop of a payable function re-uses the "
            "same msg.value on every iteration; delegated code that credits "
            "balances by msg.value counts the deposit multiple times."
        ),
        exploit_scenario=(
            "A multicall batch(bytes[]) function loops over "
            "address(this).delegatecall(calls[i]); each crafted sub-call "
            "invokes deposit() and credits msg.value again, draining the "
            "pool."
        ),
        recommendation=(
            "Never delegatecall into payable code inside a loop that relies "
            "on msg.value; track value explicitly (per-call amounts summing "
            "to msg.value) or forbid msg.value-reading functions from batch "
            "entry points."
        ),
    )

    @staticmethod
    def _dest_is_this(op: LowLevelCall, function: FunctionLike) -> bool:
        """True when the destination expression resolves to address(this)."""
        variables, _ = def_chain(function, [op.destination])
        return any(
            isinstance(var, SolidityVariable) and var.name == "this"
            for var in variables
        )

    @staticmethod
    def _contract_reads_msg_value(contract: Contract) -> bool:
        for func in contract.available_functions_from_inheritances():
            for var in func.variables_read:
                if isinstance(var, SolidityVariable) and var.name == "msg.value":
                    return True
        return False

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        seen_functions: set[int] = set()
        msg_value_readers: dict[int, bool] = {}
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.available_functions_from_inheritances():
                if id(function) in seen_functions:
                    continue
                seen_functions.add(id(function))
                if not function.payable:
                    continue
                for node in function.nodes:
                    if not node.is_inside_loop:
                        continue
                    for op in node.ir_operations:
                        if not (
                            isinstance(op, LowLevelCall)
                            and op.function_name in _DELEGATECALL_NAMES
                        ):
                            continue
                        # The delegated code path must be able to read
                        # msg.value.  For address(this) we can inspect the
                        # contract; external targets are unknown -> assumed.
                        if self._dest_is_this(op, function):
                            if id(contract) not in msg_value_readers:
                                msg_value_readers[id(contract)] = (
                                    self._contract_reads_msg_value(contract)
                                )
                            if not msg_value_readers[id(contract)]:
                                continue
                        results.append(
                            self.finding(
                                [
                                    node,
                                    " delegatecalls inside a loop of the "
                                    "payable function ",
                                    function,
                                    "; msg.value is re-used on every "
                                    "iteration",
                                ]
                            )
                        )
        return results
