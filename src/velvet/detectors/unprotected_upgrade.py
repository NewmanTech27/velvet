"""`unprotected-upgrade` detector (spec/detectors-catalog.md §2.2 — normative).

Flags upgradeable logic/implementation contracts whose ``initialize``-style
function sets privileged state (e.g. ``owner``) while the implementation
contract can still be initialized directly: there is no constructor that
disables initializers, or a destructive path (``selfdestruct``) becomes
reachable after such a takeover — the pattern behind the second Parity
multisig hack.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.analyses.read_write import expand_read_variables
from velvet.core.contract import Contract
from velvet.core.function import FunctionLike
from velvet.core.variables import SolidityVariable, StateVariable
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
    InternalCall,
    SolidityCall,
)

_GUARD_BUILTINS = ("require", "assert")
_PRIVILEGED_NAMES = {
    "owner",
    "admin",
    "administrator",
    "governor",
    "governance",
    "guardian",
    "manager",
    "operator",
    "controller",
    "authority",
}
_SELFDESTRUCT_BUILTINS = ("selfdestruct", "suicide")


def _is_initializer_name(name: str) -> bool:
    return name == "init" or name.startswith("initialize")


class UnprotectedUpgrade(Detector):
    """Detect initializable logic contracts callable on the implementation."""

    RULE = "unprotected-upgrade"
    TITLE = "Unprotected upgradeable initializer on the logic contract"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#unprotected-upgrade",
        title="Unprotected upgradeable initializer",
        description=(
            "An upgradeable logic contract exposes an initialize-style "
            "function that sets privileged state and can be called on the "
            "implementation contract itself: no constructor disables "
            "initializers, or a selfdestruct path becomes reachable after "
            "the takeover. Attackers can own the implementation directly "
            "and destroy it, bricking every proxy pointing to it."
        ),
        exploit_scenario=(
            "LogicV1.initialize sets owner = msg.sender and the "
            "implementation has no locking constructor; an attacker "
            "initializes the deployed logic contract, becomes owner and "
            "calls the owner-gated selfdestruct, bricking all proxies."
        ),
        recommendation=(
            "Add a constructor to the implementation that locks initializers "
            "(e.g. _disableInitializers()) and never expose selfdestruct or "
            "uncontrolled delegatecall in upgradeable logic."
        ),
    )

    # ------------------------------------------------------------ helpers
    def _auth_state_variables(self, contract: Contract) -> list[StateVariable]:
        """State variables compared against msg.sender in any guard."""
        result: list[StateVariable] = []
        functions: list[FunctionLike] = list(
            contract.available_functions_from_inheritances()
        ) + list(contract.all_modifiers())
        for function in functions:
            for node in function.all_nodes:
                for op in node.ir_operations:
                    reads: list[Any] = []
                    if isinstance(op, Condition):
                        reads = [op.value]
                    elif (
                        isinstance(op, SolidityCall)
                        and op.function.name in _GUARD_BUILTINS
                    ):
                        reads = op.arguments
                    else:
                        continue
                    expanded = expand_read_variables(reads, function)
                    if not any(
                        isinstance(v, SolidityVariable) and v.name == "msg.sender"
                        for v in expanded
                    ):
                        continue
                    for var in expanded:
                        if isinstance(var, StateVariable) and not any(
                            v is var for v in result
                        ):
                            result.append(var)
        return result

    @staticmethod
    def _writes_privileged(
        function: FunctionLike, auth_vars: list[StateVariable]
    ) -> bool:
        for var in function.state_variables_written:
            if any(v is var for v in auth_vars):
                return True
            if var.name.lower() in _PRIVILEGED_NAMES:
                return True
        return False

    @staticmethod
    def _has_disable_initializers(contract: Contract) -> bool:
        """True when a constructor calls a *disableInitializers* helper."""
        for function in contract.available_functions_from_inheritances():
            if not function.is_constructor:
                continue
            for op in function.all_ir_operations:
                if isinstance(op, (InternalCall, HighLevelCall)) and (
                    "disableinitializers" in op.function_name.lower()
                ):
                    return True
        return False

    @staticmethod
    def _has_selfdestruct(contract: Contract) -> bool:
        for function in contract.available_functions_from_inheritances():
            for op in function.all_ir_operations:
                if (
                    isinstance(op, SolidityCall)
                    and op.function.name in _SELFDESTRUCT_BUILTINS
                ):
                    return True
        return False

    # ------------------------------------------------------------ analysis
    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts_derived:
            if contract.is_interface or contract.is_library or contract.is_abstract:
                continue
            initializers = [
                f
                for f in contract.available_functions_from_inheritances()
                if f.is_implemented
                and not f.is_constructor
                and f.visibility in ("external", "public")
                and _is_initializer_name(f.name)
                and not f.is_protected
            ]
            if not initializers:
                continue
            auth_vars = self._auth_state_variables(contract)
            privileged = [
                f for f in initializers if self._writes_privileged(f, auth_vars)
            ]
            if not privileged:
                continue
            locked = self._has_disable_initializers(contract)
            destructive = self._has_selfdestruct(contract)
            if locked and not destructive:
                continue
            reasons: list[str] = []
            if not locked:
                reasons.append("no constructor disables initializers")
            if destructive:
                reasons.append("a selfdestruct path exists in the contract")
            for function in privileged:
                results.append(
                    self.finding(
                        [
                            function,
                            " is an unprotected initializer setting privileged"
                            " state on the implementation contract (",
                            contract,
                            f"): {'; '.join(reasons)}",
                        ]
                    )
                )
        return results
