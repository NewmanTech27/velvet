"""`events-access` detector (spec/detectors-catalog.md §2.6 — normative).

Flags privileged functions that change critical access-control state
(owner, admin, roles, ...) without emitting an event, making permission
changes hard to track off-chain.  A variable is "access-control state"
when an access-control modifier compares it against ``msg.sender``; a
function guarded by such a modifier that writes one of those guarded
variables must announce the change with an event.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.core.function import Modifier
from velvet.core.variables import StateVariable
from velvet.detectors._batch_e_utils import (
    emits_event,
    state_variables_guarded_with_msg_sender,
    unique_functions,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class EventsAccess(Detector):
    """Detect access-control changes that emit no event."""

    RULE = "events-access"
    TITLE = "Critical access-control change emits no event"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#events-access",
        title="Missing event for an access-control change",
        description=(
            "A function protected by an access-control modifier assigns a "
            "state variable used in access-control checks without emitting "
            "an event, making ownership/permission changes hard to track "
            "off-chain."
        ),
        exploit_scenario=(
            "Governed.transferGovernance(next) reassigns the governor "
            "role without an event; off-chain monitors never notice the "
            "takeover."
        ),
        recommendation=(
            "Emit an event (e.g. OwnershipTransferred) for every critical "
            "permission change."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        # Access-control modifiers and the state variables they guard.
        guarded_by_modifier: dict[int, tuple[Modifier, list[StateVariable]]] = {}
        for function in unique_functions(self.compilation_unit):
            if not isinstance(function, Modifier):
                continue
            guarded = state_variables_guarded_with_msg_sender(function)
            if guarded:
                guarded_by_modifier[id(function)] = (function, guarded)

        if not guarded_by_modifier:
            return results

        for function in unique_functions(self.compilation_unit):
            if isinstance(function, Modifier) or not function.is_implemented:
                continue
            applied = [
                guarded_by_modifier[id(mod)]
                for mod in function.modifiers
                if id(mod) in guarded_by_modifier
            ]
            if not applied:
                continue
            written = function.state_variables_written_deep
            for _modifier, guarded in applied:
                if emits_event(function):
                    break
                for var in guarded:
                    if not any(v is var for v in written):
                        continue
                    results.append(
                        self.finding(
                            [
                                function,
                                " changes the access-control state ",
                                var,
                                " without emitting an event",
                            ]
                        )
                    )
        return results
