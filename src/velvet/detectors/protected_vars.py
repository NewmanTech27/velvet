"""`protected-vars` detector (spec/detectors-catalog.md §2.3 — normative).

Flags state variables carrying a machine-readable write-protection
annotation — a NatSpec tag such as
``/// @custom:security write-protection="onlyOwner()"`` placed directly
above the declaration — that are also written by functions not applying the
named protection (modifier or check function).

The framework does not parse NatSpec into the core model, so the tag is
consumed from the source lines directly above the variable declaration.

Original clean-room implementation.
"""

from __future__ import annotations

import re
from typing import Optional

from velvet.core.function import FunctionLike
from velvet.core.variables import StateVariable
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import HighLevelCall, InternalCall, LibraryCall

_TAG_RE = re.compile(
    r"@custom:security\s+write-protection\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|(\S+))"
)
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_COMMENT_PREFIXES = ("///", "//", "/*", "*")


class ProtectedVars(Detector):
    """Detect writes that bypass a documented write-protection."""

    RULE = "protected-vars"
    TITLE = "Protected state variable written without the documented guard"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#protected-vars",
        title="Write-protection annotation violated",
        description=(
            "A state variable is documented (via a machine-readable "
            "@custom:security write-protection annotation) as only writable "
            "under a given guard, but at least one function writes it "
            "without applying the named protection."
        ),
        exploit_scenario=(
            "Config.treasury is annotated "
            'write-protection="onlyAdmin()" but migrateTreasury(t) writes '
            "it without the onlyAdmin modifier; anyone repoints the "
            "treasury and steals future payouts."
        ),
        recommendation=(
            "Add the documented access control to every function that "
            "writes the protected variable."
        ),
    )

    # ------------------------------------------------------------ helpers
    def _annotated_protection(self, var: StateVariable) -> Optional[str]:
        """Protection name from the doc comment above the declaration."""
        mapping = var.source_mapping
        if mapping.filename is None or not mapping.lines:
            return None
        source = self.session.source_code(mapping.filename.relative)
        if not source and mapping.filename.absolute != mapping.filename.relative:
            source = self.session.source_code(mapping.filename.absolute)
        if not source:
            return None
        lines = source.splitlines()
        comments: list[str] = []
        index = mapping.lines[0] - 2  # line directly above (0-based)
        while index >= 0:
            text = lines[index].strip()
            if text.startswith(_COMMENT_PREFIXES) or text.endswith("*/"):
                comments.append(text)
                index -= 1
                continue
            break
        match = _TAG_RE.search("\n".join(reversed(comments)))
        if match is None:
            return None
        raw = next(group for group in match.groups() if group)
        name = _NAME_RE.search(raw)
        return name.group(0) if name else None

    @staticmethod
    def _has_protection(function: FunctionLike, name: str) -> bool:
        """True when the function applies the named modifier or check."""
        if any(modifier.name == name for modifier in function.modifiers):
            return True
        for op in function.all_ir_operations:  # includes applied modifiers
            if (
                isinstance(op, (InternalCall, HighLevelCall, LibraryCall))
                and op.function_name == name
            ):
                return True
        return False

    # ------------------------------------------------------------ analysis
    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts_derived:
            if contract.is_interface:
                continue
            for var in contract.state_variables_ordered:
                protection = self._annotated_protection(var)
                if protection is None:
                    continue
                for function in contract.available_functions_from_inheritances():
                    if function.is_constructor or not function.is_implemented:
                        continue
                    if not any(
                        v is var for v in function.state_variables_written
                    ):
                        continue
                    if self._has_protection(function, protection):
                        continue
                    results.append(
                        self.finding(
                            [
                                function,
                                " writes ",
                                var,
                                " without its documented write-protection "
                                f'"{protection}()"',
                            ]
                        )
                    )
        return results
