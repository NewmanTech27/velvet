"""`naming-convention` detector (spec/detectors-catalog.md §8.10 — normative).

Flags identifiers that violate the Solidity style guide:
contracts/libraries/structs/enums/events in CapWords, functions/modifiers/
variables/parameters in mixedCase, constants in UPPER_CASE_WITH_UNDERSCORES.
Each declaration is checked once, at its declaration site.

Documented exceptions: ``name``/``symbol``/``decimals`` constants may be
lowercase; a leading underscore is allowed for private variables (and
private/internal functions) and unused parameters.  Identifiers without
letters (e.g. the ERC-7201 storage pointer ``$``) carry no case and cannot
violate a casing rule; a trailing underscore used to disambiguate parameters
and locals from state variables is likewise tolerated by mixedCase, which
still requires a lowercase start.

Original clean-room implementation.
"""

from __future__ import annotations

import re
from typing import Any, Iterator, Optional

from velvet.core.contract import Contract
from velvet.core.function import FunctionKind
from velvet.core.variables import LocalVariable
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

CAP_WORDS = "CapWords"
MIXED_CASE = "mixedCase"
UPPER_CASE = "UPPER_CASE_WITH_UNDERSCORES"

# ``$`` is a legal Solidity identifier character with no case (used by the
# ERC-7201 storage-pointer idiom, e.g. a local named ``$``); a trailing
# underscore is a widely used suffix to disambiguate parameters/locals from
# state variables (OpenZeppelin/CMTAT house style).  Neither constitutes a
# casing violation, so the mixedCase rule tolerates both while still
# requiring a lowercase start.  CapWords keeps its strict interior form.
_CAP_WORDS_RE = re.compile(r"^[A-Z][a-zA-Z0-9$]*$")
_MIXED_CASE_RE = re.compile(r"^[a-z][a-zA-Z0-9$]*_*$")
_UPPER_CASE_RE = re.compile(r"^[A-Z][A-Z0-9_$]*$")
_HAS_LETTER_RE = re.compile(r"[a-zA-Z]")

#: ERC-20 metadata constants documented as allowed to be lowercase.
_ERC20_METADATA = {"name", "symbol", "decimals"}


def _matches(
    identifier: str, convention: str, allow_leading_underscore: bool = False
) -> bool:
    # The documented exception allows *a* leading underscore for private
    # variables and unused parameters (catalog §8.10); it is not a blank
    # cheque — ``__gap`` (two underscores) and ``_interfaceId`` on a *used*
    # parameter are still violations.
    candidate = identifier
    if allow_leading_underscore and candidate.startswith("_"):
        candidate = candidate[1:]
    if not candidate or not _HAS_LETTER_RE.search(candidate):
        return True  # "_" / "$" alone (no letter, no case) is acceptable
    if convention == CAP_WORDS:
        return bool(_CAP_WORDS_RE.match(candidate))
    if convention == MIXED_CASE:
        return bool(_MIXED_CASE_RE.match(candidate))
    if convention == UPPER_CASE:
        return bool(_UPPER_CASE_RE.match(candidate))
    return True  # pragma: no cover - unknown convention


class NamingConvention(Detector):
    """Detect identifiers that violate the Solidity naming style guide."""

    RULE = "naming-convention"
    TITLE = "Solidity naming convention violation"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#naming-convention",
        title="Conformance to Solidity naming conventions",
        description=(
            "Identifiers that violate the Solidity style guide: "
            "contracts/libraries in CapWords, functions/variables in "
            "mixedCase, constants in UPPER_CASE_WITH_UNDERSCORES."
        ),
        exploit_scenario=(
            "contract my_token declares `uint256 public TOTAL;` (should be "
            "mixedCase) and `uint256 constant maxSupply;` (should be "
            "MAX_SUPPLY), confusing reviewers and tooling."
        ),
        recommendation="Rename identifiers to follow the Solidity style guide.",
    )

    # ------------------------------------------------------------- checks
    def _check(
        self,
        results: list[Finding],
        decl: Any,
        convention: str,
        kind: str,
        context: Optional[str] = None,
        allow_leading_underscore: bool = False,
    ) -> None:
        name = getattr(decl, "name", "") or ""
        if not name or _matches(name, convention, allow_leading_underscore):
            return
        # The parent context disambiguates distinct same-name declarations
        # in one file (e.g. two functions taking an `ERC20Attributes_`
        # parameter): they are separate findings, not duplicates.
        where = f" of {context}" if context else ""
        results.append(
            self.finding(
                [decl, f" ({kind}{where}) should be named in {convention}"],
                additional_fields={"convention": convention, "declaration_kind": kind},
            )
        )

    @staticmethod
    def _is_private(decl: Any) -> bool:
        return getattr(decl, "visibility", None) in ("private", "internal")

    @staticmethod
    def _used_variable_ids(func: Any) -> frozenset:
        try:
            return frozenset(id(v) for v in func.variables_read)
        except Exception:  # pragma: no cover - analysis unavailable
            return frozenset()

    def _contract_declarations(
        self, contract: Contract
    ) -> Iterator[tuple[Any, str, str, Optional[str], bool]]:
        """(declaration, convention, kind, parent-context, allow-underscore)."""
        yield contract, CAP_WORDS, "contract", None, False
        for struct in contract.structures:
            yield struct, CAP_WORDS, "struct", None, False
        for enum in contract.enums:
            yield enum, CAP_WORDS, "enum", None, False
        for event in contract.events:
            yield event, CAP_WORDS, "event", None, False
        for var in contract.state_variables:
            allow = self._is_private(var)
            if var.is_constant:
                if var.name in _ERC20_METADATA:
                    continue  # documented lowercase exception
                yield var, UPPER_CASE, "constant state variable", None, allow
            else:
                yield var, MIXED_CASE, "state variable", None, allow
        for func in contract.functions:
            if func.kind != FunctionKind.NORMAL:
                continue  # constructor / fallback / receive have fixed names
            yield func, MIXED_CASE, "function", None, self._is_private(func)
            used = self._used_variable_ids(func)
            for param in func.parameters:
                yield param, MIXED_CASE, "function parameter", str(func), (
                    id(param) not in used
                )
            for ret in func.returns:
                yield ret, MIXED_CASE, "return variable", str(func), True
        for modifier in contract.modifiers:
            yield modifier, MIXED_CASE, "modifier", None, self._is_private(modifier)
            used = self._used_variable_ids(modifier)
            for param in modifier.parameters:
                yield param, MIXED_CASE, "modifier parameter", str(modifier), (
                    id(param) not in used
                )
        for func in contract.functions_and_modifiers:
            for node in func.nodes:
                decl = node.variable_declaration
                if isinstance(decl, LocalVariable):
                    yield decl, MIXED_CASE, "local variable", str(func), True

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        seen: set[int] = set()
        for contract in self.compilation_unit.contracts:
            for decl, convention, kind, context, allow in self._contract_declarations(contract):
                if id(decl) in seen:
                    continue
                seen.add(id(decl))
                self._check(results, decl, convention, kind, context, allow)
        for func in self.compilation_unit.top_level_functions:
            self._check(results, func, MIXED_CASE, "function")
        for var in self.compilation_unit.top_level_variables:
            if var.is_constant:
                self._check(results, var, UPPER_CASE, "constant variable")
            else:
                self._check(results, var, MIXED_CASE, "variable")
        return results
