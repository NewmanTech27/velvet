"""`pyth-unchecked-confidence` detector (spec/detectors-catalog.md §6.2 —
normative).

Flags Pyth price consumptions that never validate the confidence interval
(``conf``).  A wide confidence interval means the reported price is
unreliable; using it raw enables mispriced trades and liquidations.  The
``conf`` field is never enforced by the Pyth API itself, so the consumer
must bound it.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_f_utils import (
    is_oracle_call,
    tuple_unpack,
    unique_functions,
    value_reaches_check,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

#: Pyth getters returning the (price, conf, expo, publishTime) tuple.
_PRICE_GETTERS = (
    "getPrice",
    "getEmaPrice",
    "getPriceUnsafe",
    "getEmaPriceUnsafe",
    "getPriceNoOlderThan",
    "getEmaPriceNoOlderThan",
)

#: Interface-name keyword identifying a Pyth price-feed contract.
_PYTH_KEYWORD = "pyth"

#: Tuple index of the ``conf`` field in the Pyth price struct.
_CONF_INDEX = 1


class PythUncheckedConfidence(Detector):
    """Detect Pyth prices used without bounding the confidence interval."""

    RULE = "pyth-unchecked-confidence"
    TITLE = "Pyth price used without checking the confidence interval"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#pyth-unchecked-confidence",
        title="Pyth price used without checking the confidence interval",
        description=(
            "A Pyth price is consumed without validating its confidence "
            "interval (conf). A wide confidence interval means the reported "
            "price is unreliable; using it raw enables mispriced trades and "
            "liquidations."
        ),
        exploit_scenario=(
            "borrowValue() uses pyth.getPriceUnsafe(id) and ignores conf; "
            "during a volatility spike Pyth reports a wide interval, the "
            "protocol treats the midpoint as exact, and borrowers mint "
            "undercollateralized debt."
        ),
        recommendation=(
            "Check the confidence interval against a maximum acceptable "
            "ratio (e.g. conf/price) before using the price."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            for node in function.nodes:
                for op in node.ir_operations:
                    if not is_oracle_call(op, _PRICE_GETTERS, _PYTH_KEYWORD):
                        continue
                    unpack = tuple_unpack(function, op.lvalue, _CONF_INDEX)
                    if unpack is not None and value_reaches_check(
                        function, unpack.lvalue
                    ):
                        continue  # conf extracted and validated somewhere
                    results.append(
                        self.finding(
                            [
                                node,
                                " consumes a Pyth price in ",
                                function,
                                " without validating its confidence interval "
                                "(conf)",
                            ]
                        )
                    )
        return results
