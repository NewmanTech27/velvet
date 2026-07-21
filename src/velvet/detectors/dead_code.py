"""`dead-code` detector (spec/detectors-catalog.md §8.17 — normative).

Flags internal/private functions and library routines with no call sites in
the call graph reachable from the contract's public entry points.  Dead
code increases audit surface and usually signals incomplete refactors.

Entry-point reachability is computed per most-derived contract (so
inherited functions are judged in the context in which they can actually
be deployed); a candidate is reported when no derived contract reaches it.
Constructors count as entry points (their bodies run at deployment), and
reachability follows internal calls, library calls, modifier bodies,
resolvable internal dynamic calls, and virtual dispatch (an internal call
to a base/virtual implementation may execute any of its overrides — so an
override used across the inheritance family is never "never used").

Only functions declared in the analyzed project sources are reported:
dependency code (``node_modules``, ``lib/``, vendored packages) is out of
scope for the audit surface, matching the catalog's "never used" intent.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.analyses.reachability import internal_calls_reachable
from velvet.compile.artifacts import is_dependency_path
from velvet.core.function import FunctionKind
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


def _declared_in_dependency(function: object) -> bool:
    """True when the function's declaration site is dependency code."""
    filename = getattr(getattr(function, "source_mapping", None), "filename", None)
    if filename is None:
        return False
    return is_dependency_path(filename.absolute)


class DeadCode(Detector):
    """Detect functions never reachable from any entry point."""

    RULE = "dead-code"
    TITLE = "Function is never called"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#dead-code",
        title="Function is never called",
        description=(
            "An internal function or library routine with no call sites in "
            "the call graph reachable from the contract's public entry "
            "points; dead code increases audit surface and usually signals "
            "incomplete refactors."
        ),
        exploit_scenario=(
            "oldHash(bytes) was replaced by a new hashing helper but never "
            "removed; auditors must review code that can never execute."
        ),
        recommendation="Delete unused functions, or wire them into the intended call paths.",
    )

    def analyze(self) -> list[Finding]:
        # Reachable functions per most-derived contract: its entry points
        # (public/external functions plus the constructor) and everything
        # they can reach through internal/library/virtual-dispatched calls.
        reachable_sets: list[set[int]] = []
        for contract in self.compilation_unit.contracts_derived:
            reachable: set[int] = set()
            entries = list(contract.functions_entry_points)
            entries.extend(f for f in contract.functions if f.is_constructor)
            for entry in entries:
                reachable.add(id(entry))
                for target in internal_calls_reachable(entry):
                    reachable.add(id(target))
            reachable_sets.append(reachable)

        results: list[Finding] = []
        seen: set[int] = set()
        for contract in self.compilation_unit.contracts:
            if contract.is_interface:
                continue
            for function in contract.functions:
                if id(function) in seen:
                    continue
                if function.visibility not in ("internal", "private"):
                    continue
                if function.kind != FunctionKind.NORMAL:
                    continue
                if not function.is_implemented:
                    continue
                if _declared_in_dependency(function):
                    continue
                seen.add(id(function))
                if any(id(function) in reachable for reachable in reachable_sets):
                    continue
                results.append(
                    self.finding(
                        [
                            function,
                            " is never called from any public entry point"
                            " in ",
                            contract,
                        ]
                    )
                )
        return results
