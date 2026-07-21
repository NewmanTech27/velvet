"""`constant-function-state` detector (spec/detectors-catalog.md §5.8 —
normative).

Flags functions declared ``constant``/``view``/``pure`` that change state
through ordinary Solidity statements (state-variable writes, event
emissions, contract creations, ``selfdestruct``, Ether-moving or value
low-level calls), in code compiled before Solidity 0.5.  Pre-0.5 compilers
allow it; 0.5+ callers use ``STATICCALL`` and will always revert.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.function import FunctionLike
from velvet.detectors._batch_g_utils import compiled_before
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import (
    EventCall,
    LowLevelCall,
    NewContract,
    Send,
    SolidityCall,
    Transfer,
)

#: The constant-function attributes were unenforced before solc 0.5.
FIXED_VERSION = "0.5.0"

_SELFDESTRUCT_BUILTINS = ("selfdestruct", "suicide")


def _state_changes(function: FunctionLike) -> list[str]:
    """Descriptions of the state-changing operations in ``function``."""
    changes: list[str] = []
    written = function.state_variables_written
    if written:
        names = ", ".join(v.name for v in written)
        changes.append(f"writes state variable(s) {names}")
    for op in function.all_ir_operations:
        if isinstance(op, EventCall):
            changes.append(f"emits event {op.name}")
        elif isinstance(op, NewContract):
            changes.append(f"creates contract {op.contract_name}")
        elif isinstance(op, SolidityCall) and op.function.name in _SELFDESTRUCT_BUILTINS:
            changes.append(f"calls {op.function.name}")
        elif isinstance(op, LowLevelCall) and op.call_value is not None:
            changes.append(f"performs a low-level {op.function_name} with value")
        elif isinstance(op, (Send, Transfer)):
            changes.append("moves Ether")
    return changes


class ConstantFunctionState(Detector):
    """Detect constant/view/pure functions that change state (pre-0.5)."""

    RULE = "constant-function-state"
    TITLE = "Constant/view/pure function changes the state"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#constant-function-state",
        title="State change in a constant/view/pure function (pre-0.5 compiler)",
        description=(
            "A function declared constant/view/pure performs a state-changing "
            "operation (state variable write, event emission, contract "
            "creation, selfdestruct, value transfer). Before Solidity 0.5 "
            "the compiler did not enforce these attributes; callers compiled "
            "with >= 0.5 use STATICCALL, so every such call reverts."
        ),
        exploit_scenario=(
            "Stats.total() is declared constant but increments the queries "
            "counter under solc 0.4.24; a 0.8 caller static-calls it and "
            "always reverts, freezing the dependent contract."
        ),
        recommendation=(
            "Correct the function's mutability declaration or remove the "
            "state change; verify legacy contracts before calling them "
            "from 0.5+ code."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        if not compiled_before(self.compilation_unit, FIXED_VERSION):
            return results
        for contract in self.compilation_unit.contracts:
            for function in contract.functions_and_modifiers:
                if not (function.view or function.pure):
                    continue
                if not function.is_implemented:
                    continue
                changes = _state_changes(function)
                if not changes:
                    continue
                results.append(
                    self.finding(
                        [
                            function,
                            " is declared constant/view/pure but ",
                            "; ".join(changes),
                            " (attribute not enforced by solc "
                            f"{self.compilation_unit.solc_version})",
                        ]
                    )
                )
        return results
