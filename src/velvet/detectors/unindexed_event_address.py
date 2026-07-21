"""`unindexed-event-address` detector (spec/detectors-catalog.md §8.15 —
normative).

Flags events that carry ``address`` parameters but index none of their
parameters: off-chain consumers filter logs by indexed topics, so an
address-bearing event with no ``indexed`` field cannot be efficiently
filtered by sender/recipient.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.core.types import ElementaryType
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


def _is_address(type_: Any) -> bool:
    return isinstance(type_, ElementaryType) and type_.name.split()[0] == "address"


class UnindexedEventAddress(Detector):
    """Detect address-bearing events with no indexed parameter."""

    RULE = "unindexed-event-address"
    TITLE = "Event with address parameters indexes none of them"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#unindexed-event-address",
        title="Event with address parameters indexes none of them",
        description=(
            "An event declares at least one address-typed parameter but "
            "marks no parameter indexed; external tooling cannot filter "
            "the logs by sender/recipient through the block bloom filter."
        ),
        exploit_scenario=(
            "Registry emits UserRegistered(user, id) with no indexed "
            "field; a block explorer cannot select registrations for one "
            "user without replaying every log."
        ),
        recommendation=(
            "Mark up to three relevant parameters (typically the "
            "addresses) indexed."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        seen: set[int] = set()
        for contract in self.compilation_unit.contracts:
            for event in contract.events:
                if id(event) in seen:
                    continue
                seen.add(id(event))
                if not any(_is_address(param.type) for param in event.elems):
                    continue
                if any(param.indexed for param in event.elems):
                    continue
                results.append(
                    self.finding(
                        [
                            event,
                            " carries address parameter(s) but indexes "
                            "none of its parameters in ",
                            contract,
                            "; logs cannot be filtered by address",
                        ]
                    )
                )
        return results
