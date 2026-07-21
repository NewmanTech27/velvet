"""`external-function` detector (spec/detectors-catalog.md §9.5 — normative).

Flags ``public`` functions that are never called internally.  Declaring them
``external`` lets arguments stay in ``calldata`` (avoiding a copy to memory)
and clarifies the API surface.  Functions required to be ``public`` are
exempt: those called internally (including ``super.f()``), those overriding
or implementing an inherited declaration (an explicit ``override`` is *not*
required to implement an interface function, so any matching ancestor
declaration exempts the function), and those declared in abstract contracts,
interfaces/libraries, or any contract that is inherited — such contracts are
inheritance APIs whose consumers (possibly outside the analyzed set) may
rely on ``public`` visibility for internal/super calls.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.function import Function, FunctionKind
from velvet.core.variables import SolidityVariable
from velvet.detectors._batch_f_utils import unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import HighLevelCall, InternalCall

_SKIP_KINDS = (FunctionKind.CONSTRUCTOR, FunctionKind.FALLBACK, FunctionKind.RECEIVE)


class ExternalFunction(Detector):
    """Detect public functions that should be external."""

    RULE = "external-function"
    TITLE = "Public function that is never called internally"
    IMPACT = Impact.OPTIMIZATION
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#external-function",
        title="Public function that is never called internally",
        description=(
            "A public function is never called internally. Declaring it "
            "external lets arguments stay in calldata (avoiding a copy to "
            "memory) and clarifies the API surface."
        ),
        exploit_scenario=(
            "mint(address to, uint256 amount) public is only ever called by "
            "EOAs; every call copies its calldata arguments to memory, "
            "wasting gas on each invocation."
        ),
        recommendation=(
            "Change public to external (and prefer calldata for array/struct "
            "parameters)."
        ),
    )

    def _internal_callers(self) -> tuple[set[int], set[str]]:
        """Internal-call target ids and names invoked via ``this.f()``."""
        internal_targets: set[int] = set()
        this_calls: set[str] = set()
        for function in unique_functions(self.compilation_unit):
            for op in function.all_ir_operations:
                if isinstance(op, InternalCall) and op.function is not None:
                    internal_targets.add(id(op.function))
                elif (
                    isinstance(op, HighLevelCall)
                    and isinstance(op.destination, SolidityVariable)
                    and op.destination.name == "this"
                ):
                    this_calls.add(op.function_name)
        return internal_targets, this_calls

    @staticmethod
    def _implements_inherited_declaration(function: Function) -> bool:
        """The function's signature is declared by an ancestor contract.

        Implementing an interface (or base) function does not require the
        ``override`` keyword in Solidity, so ``function.overrides`` alone
        misses interface implementations; any matching ancestor declaration
        means the visibility is constrained for interface/override reasons.
        """
        declarer = function.contract_declarer or function.contract
        if declarer is None:
            return False
        for base in declarer.inheritance:
            for candidate in base.functions:
                if candidate.signature == function.signature:
                    return True
        return False

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        internal_targets, this_calls = self._internal_callers()
        for function in unique_functions(self.compilation_unit):
            if not isinstance(function, Function):
                continue  # functions only, not modifiers
            if function.visibility != "public":
                continue
            if function.kind in _SKIP_KINDS or function.is_constructor:
                continue
            if not function.is_implemented:
                continue  # interface / abstract declaration
            declarer = function.contract_declarer or function.contract
            if declarer is not None and (
                declarer.is_interface or declarer.is_library or declarer.is_abstract
            ):
                continue
            if declarer is not None and declarer.derived_contracts:
                # Inherited contracts are inheritance APIs: derived contracts
                # (possibly outside the analyzed set, e.g. framework
                # consumers) may rely on `public` for internal/super calls or
                # override compatibility.
                continue
            if function.overrides:
                continue  # required to be public for override reasons
            if self._implements_inherited_declaration(function):
                continue  # implements an interface/base declaration
            if id(function) in internal_targets or function.name in this_calls:
                continue  # called internally
            results.append(
                self.finding(
                    [
                        function,
                        " is public but never called internally; declare it "
                        "external to keep arguments in calldata",
                    ]
                )
            )
        return results
