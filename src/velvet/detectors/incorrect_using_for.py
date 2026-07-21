"""`incorrect-using-for` detector (spec/detectors-catalog.md §8.7 —
normative).

Flags ``using Library for Type;`` statements where the library declares no
function whose first parameter matches ``Type``.  The statement has no
effect; the compiler accepts it, so the author's intent (extended methods
on the type) silently fails.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Iterator, Optional

from velvet.core.contract import Contract
from velvet.core.declarations import UsingForDirective
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


def _first_parameter_types(library: Contract) -> list[str]:
    """Normalized first-parameter type strings of the library's functions."""
    types: list[str] = []
    for function in library.functions:
        if not function.parameters:
            continue
        param_type = function.parameters[0].type
        types.append(str(param_type) if param_type is not None else "")
    return types


class IncorrectUsingFor(Detector):
    """Detect using-for directives that attach no matching library function."""

    RULE = "incorrect-using-for"
    TITLE = "using-for directive binds a library with no matching function"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#incorrect-using-for",
        title="Incorrect using-for statement",
        description=(
            "A using Library for Type statement where the library declares "
            "no function whose first parameter matches Type. The directive "
            "has no effect; the compiler accepts it, so the author's "
            "intent silently fails."
        ),
        exploit_scenario=(
            "Data declares using Strings for bytes32, but Strings only "
            "offers len(string memory); blob.len() never compiles and the "
            "planned string helpers are never wired to bytes32."
        ),
        recommendation=(
            "Attach the library to a type its functions actually accept, "
            "or add a matching function to the library."
        ),
    )

    def _resolve_library(self, directive: UsingForDirective) -> Optional[Contract]:
        library = directive.library
        if isinstance(library, Contract):
            return library
        if directive.library_name:
            return self.compilation_unit.get_contract_from_name(directive.library_name)
        return None

    def _directives(self) -> Iterator[tuple[UsingForDirective, Optional[Contract]]]:
        """Every using-for directive once, with its enclosing contract (if any)."""
        seen: set[int] = set()
        for contract in self.compilation_unit.contracts:
            for directive in contract.using_for:
                if id(directive) in seen:
                    continue
                seen.add(id(directive))
                yield directive, contract
        for directive in self.compilation_unit.using_for:
            if id(directive) in seen:
                continue
            seen.add(id(directive))
            yield directive, None

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for directive, contract in self._directives():
            library = self._resolve_library(directive)
            if library is None:
                continue
            first_types = _first_parameter_types(library)
            if directive.type is None:
                # `using L for *`: any first parameter matches, so only an
                # empty library is a no-op.
                if library.functions:
                    continue
                mismatch: Any = "no functions at all"
            else:
                target = str(directive.type)
                if target in first_types:
                    continue
                mismatch = target
            location = contract if contract is not None else library
            results.append(
                self.finding(
                    [
                        directive,
                        " in ",
                        location,
                        f" attaches library {library.name} to {mismatch}, but "
                        f"{library.name} declares no function whose first "
                        "parameter matches — the directive has no effect",
                    ]
                )
            )
        return results
