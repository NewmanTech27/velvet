"""`pyth-unchecked-publishtime` detector (spec/detectors-catalog.md §6.3 —
normative).

Flags prices fetched through a Pyth ``*Unsafe`` getter that are used without
checking ``publishTime``.  The ``Unsafe`` variants do not enforce freshness,
so a stale price may drive economic decisions unless the consumer validates
its age.

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

#: Pyth ``*Unsafe`` getters that do not enforce price freshness.
_UNSAFE_GETTERS = ("getPriceUnsafe", "getEmaPriceUnsafe")

#: Interface-name keyword identifying a Pyth price-feed contract.
_PYTH_KEYWORD = "pyth"

#: Tuple index of the ``publishTime`` field in the Pyth price struct.
_PUBLISH_TIME_INDEX = 3


class PythUncheckedPublishtime(Detector):
    """Detect stale-risk Pyth prices used without a publishTime check."""

    RULE = "pyth-unchecked-publishtime"
    TITLE = "Pyth Unsafe price used without checking publishTime"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#pyth-unchecked-publishtime",
        title="Pyth Unsafe price used without checking publishTime",
        description=(
            "A price fetched through a Pyth *Unsafe getter (which does not "
            "enforce freshness) is used without checking its publishTime, so "
            "a stale price may drive economic decisions."
        ),
        exploit_scenario=(
            "rate() reads pyth.getEmaPriceUnsafe(id) and never checks "
            "publishTime; when the Pyth pushers pause, the contract keeps "
            "pricing swaps off a hours-old price and is arbitraged."
        ),
        recommendation=(
            "Verify publishTime is recent (e.g. publishTime >= "
            "block.timestamp - maxAge) or use the NoOlderThan variants which "
            "enforce freshness."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            for node in function.nodes:
                for op in node.ir_operations:
                    if not is_oracle_call(op, _UNSAFE_GETTERS, _PYTH_KEYWORD):
                        continue
                    unpack = tuple_unpack(function, op.lvalue, _PUBLISH_TIME_INDEX)
                    if unpack is not None and value_reaches_check(
                        function, unpack.lvalue
                    ):
                        continue  # publishTime extracted and validated
                    results.append(
                        self.finding(
                            [
                                node,
                                " consumes a Pyth Unsafe price in ",
                                function,
                                " without checking its publishTime (staleness)",
                            ]
                        )
                    )
        return results
