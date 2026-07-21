"""`chronicle-unchecked-price` detector (spec/detectors-catalog.md §6.4 —
normative).

Flags consumption of a Chronicle oracle ``read()`` result without checking
that the feed is currently valid/active.  Chronicle feeds can be deprecated
or become inactive, and the raw ``read()`` does not tell the caller; the
validity-aware ``tryRead``/``readWithAge`` patterns surface that.

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

#: Chronicle raw read entry points that carry no validity signal.
_RAW_READS = ("read",)

#: Interface-name keyword identifying a Chronicle oracle contract.
_CHRONICLE_KEYWORD = "chronicle"


class ChronicleUncheckedPrice(Detector):
    """Detect Chronicle read() used without a validity check."""

    RULE = "chronicle-unchecked-price"
    TITLE = "Chronicle read() used without checking feed validity"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#chronicle-unchecked-price",
        title="Chronicle read() used without checking feed validity",
        description=(
            "A Chronicle oracle read() result is consumed without checking "
            "that the feed is currently valid/active. Chronicle feeds can be "
            "deprecated or become inactive; the raw read() does not tell the "
            "caller."
        ),
        exploit_scenario=(
            "ethUsd() returns feed.read(); the Chronicle feed is sunset and "
            "starts returning a stale/zero value, and the lending market "
            "priced off it is drained."
        ),
        recommendation=(
            "Use the validity-aware read (tryRead / readWithAge patterns) "
            "and revert when the feed is invalid or stale."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            for node in function.nodes:
                for op in node.ir_operations:
                    if not is_oracle_call(op, _RAW_READS, _CHRONICLE_KEYWORD):
                        continue
                    results.append(
                        self.finding(
                            [
                                node,
                                " consumes a Chronicle read() result in ",
                                function,
                                " without checking the feed's validity",
                            ]
                        )
                    )
        return results
