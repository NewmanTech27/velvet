"""`pyth-deprecated-functions` detector (spec/detectors-catalog.md §6.1 —
normative).

Flags calls to the deprecated Pyth Network price-feed getters (``getPrice``,
``getEmaPrice``).  These legacy entry points revert when the price is older
than a threshold baked into the API and are superseded by the
``*NoOlderThan`` / ``*Unsafe`` variants that make staleness handling
explicit.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_f_utils import is_oracle_call, unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

#: Deprecated Pyth getters superseded by explicit-staleness variants.
_DEPRECATED_GETTERS = ("getPrice", "getEmaPrice")

#: Interface-name keyword identifying a Pyth price-feed contract.
_PYTH_KEYWORD = "pyth"


class PythDeprecatedFunctions(Detector):
    """Detect calls to deprecated Pyth price-feed getters."""

    RULE = "pyth-deprecated-functions"
    TITLE = "Deprecated Pyth price-feed function used"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#pyth-deprecated-functions",
        title="Deprecated Pyth price-feed function used",
        description=(
            "A deprecated Pyth getter (getPrice, getEmaPrice) is called. "
            "These legacy entry points revert when the price is older than a "
            "threshold baked into the API; the NoOlderThan/Unsafe variants "
            "with explicit staleness handling supersede them."
        ),
        exploit_scenario=(
            "quote() calls pyth.getPrice(id); a Pyth API update tightens the "
            "staleness window and every quote starts reverting, halting the "
            "protocol that depends on it."
        ),
        recommendation=(
            "Migrate to the current Pyth API (getPriceNoOlderThan, "
            "getPriceUnsafe, ...) and handle staleness explicitly."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            for node in function.nodes:
                for op in node.ir_operations:
                    if not is_oracle_call(op, _DEPRECATED_GETTERS, _PYTH_KEYWORD):
                        continue
                    results.append(
                        self.finding(
                            [
                                node,
                                " calls the deprecated Pyth getter ",
                                op.function_name,
                                " in ",
                                function,
                                "; use the *NoOlderThan/*Unsafe variants instead",
                            ]
                        )
                    )
        return results
