"""`optimism-deprecation` detector (spec/detectors-catalog.md §7.30 —
normative).

Flags calls to deprecated Optimism predeploy functions — notably
``scalar()`` of the ``GasPriceOracle`` predeploy
(``0x420000000000000000000000000000000000000F``), removed by the Ecotone
upgrade: it always reverts, so contracts calling it break on current
OP-stack chains.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Optional

from velvet.core.expressions import Literal, TypeConversion
from velvet.core.variables import Constant, StateVariable
from velvet.detectors._batch_e_utils import unique_functions
from velvet.detectors._batch_h_utils import literal_address
from velvet.detectors._reentrancy_common import expand_terminal_sources
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import HighLevelCall, LibraryCall

#: GasPriceOracle predeploy (OP-stack); ``scalar()`` reverts post-Ecotone.
GAS_PRICE_ORACLE = 0x420000000000000000000000000000000000000F

#: Deprecated (predeploy address, removed function name) pairs.
DEPRECATED_FUNCTIONS = ((GAS_PRICE_ORACLE, "scalar"),)


def _initializer_literal(expression: Any, *, _depth: int = 0) -> Optional[int]:
    """Int payload of a constant initializer expression, if literal."""
    if expression is None or _depth > 16:
        return None
    if isinstance(expression, Literal):
        return literal_address(expression.value)
    if isinstance(expression, TypeConversion):
        return _initializer_literal(expression.expression, _depth=_depth + 1)
    return None


def _resolves_to(source: Any, address: int) -> bool:
    """True when the expanded source leaf denotes ``address``."""
    if isinstance(source, Constant):
        return literal_address(source.value) == address
    if isinstance(source, StateVariable):
        return _initializer_literal(source.expression_initial) == address
    return False


class OptimismDeprecation(Detector):
    """Detect calls to deprecated Optimism predeploy functions."""

    RULE = "optimism-deprecation"
    TITLE = "Call to a deprecated Optimism predeploy function"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#optimism-deprecation",
        title="Call to a deprecated Optimism predeploy function",
        description=(
            "The GasPriceOracle predeploy's scalar() function was "
            "deprecated by the Ecotone upgrade and always reverts; "
            "contracts calling it break on current OP-stack chains."
        ),
        exploit_scenario=(
            "L2Fee.feeScalar() returns GPO.scalar() where GPO is the "
            "GasPriceOracle predeploy 0x4200...000F; every call reverts "
            "after Ecotone, bricking any fee logic built on it."
        ),
        recommendation=(
            "Stop calling the deprecated function; read blob/base-fee "
            "scalars through the updated GasPriceOracle API "
            "(e.g. baseFeeScalar()/blobBaseFeeScalar()) or the "
            "replacement contracts."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            for node in function.nodes:
                for op in node.ir_operations:
                    if not isinstance(op, HighLevelCall) or isinstance(
                        op, LibraryCall
                    ):
                        continue
                    for address, name in DEPRECATED_FUNCTIONS:
                        if op.function_name != name:
                            continue
                        leaves = expand_terminal_sources(
                            [op.destination], function
                        )
                        if not any(
                            _resolves_to(leaf, address) for leaf in leaves
                        ):
                            continue
                        results.append(
                            self.finding(
                                [
                                    node,
                                    f" calls the deprecated {name}() of the "
                                    f"Optimism predeploy {hex(address)} in ",
                                    function,
                                    "; it always reverts on post-Ecotone "
                                    "OP-stack chains",
                                ]
                            )
                        )
                        break
        return results
