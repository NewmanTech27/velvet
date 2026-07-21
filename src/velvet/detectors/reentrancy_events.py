"""`reentrancy-events` detector (spec/detectors-catalog.md §1.5 — normative).

Flags events emitted after a re-enterable external call when the event's
parameters depend on contract state: a re-entrant execution produces
out-of-order or duplicated event values, misleading off-chain consumers
(indexers, bridges, accounting) that trust event sequences.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.variables import StateVariable
from velvet.detectors._reentrancy_common import (
    expand_terminal_sources,
    function_call_contexts,
    iter_analyzable_functions_with_contract,
    owner_function,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class ReentrancyEvents(Detector):
    """Detect event emissions whose ordering reentrancy can corrupt."""

    RULE = "reentrancy-events"
    TITLE = "Reentrancy corrupting event order or values"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#reentrancy-events",
        title="Reentrancy corrupting event order or values",
        description=(
            "A function emits an event whose parameters depend on state that "
            "can change during an external call made earlier in the same "
            "function, so a re-entrant execution produces out-of-order or "
            "duplicated event values."
        ),
        exploit_scenario=(
            "Counter.count increments a counter, calls an attacker-supplied "
            "callback and only then emits Counted(n); a re-entrant execution "
            "emits later Counted values before earlier ones, confusing the "
            "indexer that mirrors the counter off-chain."
        ),
        recommendation=(
            "Emit events before external calls "
            "(checks-effects-interactions), or make off-chain consumers "
            "robust to reordering."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract, function in iter_analyzable_functions_with_contract(
                self.compilation_unit
            ):
            for context in function_call_contexts(function, contract=contract):
                for event_op, event_node in context.events_after:
                    owner = owner_function(event_node, function)
                    expanded = expand_terminal_sources(event_op.arguments, owner)
                    state_deps = [v for v in expanded if isinstance(v, StateVariable)]
                    if not state_deps:
                        continue
                    results.append(
                        self.finding(
                            [
                                event_node,
                                " emits an event depending on ",
                                state_deps[0],
                                " after a re-enterable external call (",
                                context.node,
                                ") in ",
                                function,
                            ]
                        )
                    )
        return results
