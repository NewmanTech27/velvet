"""`too-many-digits` detector (spec/detectors-catalog.md §8.18 — normative).

Flags numeric literals with many digits that are hard to read and review
(``10000000000000000000`` — is that 1e18 or 1e19?).  Miscounting zeros is a
classic source of 10x/100x value bugs.  Literals written with scientific
notation (``1e20``) or digit separators (``100_000_000``) read fine and are
exempt; a plain long run of digits — decimal or hexadecimal — is reported.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Iterator

from velvet.core.cfg_node import NodeKind
from velvet.core.expressions import Literal
from velvet.core.variables import Constant
from velvet.detectors._batch_f_utils import unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

#: Plain decimal literals with more than this many digits are reported
#: (the catalog's own example flags the 8-digit ``10000000``).
MAX_DIGITS = 7

#: Hexadecimal literals with more than this many hex digits are reported.
#: 16 hex digits (a 64-bit mask) stay reviewable; 32/64-digit masks
#: (``0xFFFFFFFF00000000FFFFFFFF00000000``) are as error-prone to eyeball
#: as long decimal runs.
MAX_HEX_DIGITS = 16


class TooManyDigits(Detector):
    """Detect hard-to-read numeric literals with many digits."""

    RULE = "too-many-digits"
    TITLE = "Numeric literal has too many digits"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#too-many-digits",
        title="Numeric literal has too many digits",
        description=(
            "A numeric literal is written as a long run of digits without "
            "ether/time suffixes, scientific notation, or digit separators. "
            "Miscounting the zeros is a classic source of 10x/100x value "
            "bugs."
        ),
        exploit_scenario=(
            "CAP is typed as 100000000000000000000 (one zero too many); the "
            "presale cap is 10x the intended value and the raise over-collects."
        ),
        recommendation=(
            "Use ether/time suffixes (100 ether), scientific notation (1e20), "
            "or digit separators (100_000_000) for long literals."
        ),
    )

    def _literals(self) -> Iterator[Literal]:
        """Yield every numeric literal (function bodies + state initializers)."""
        seen: set[int] = set()

        def emit(expr: Any) -> Iterator[Literal]:
            for node in expr.walk():
                if isinstance(node, Literal) and id(node) not in seen:
                    seen.add(id(node))
                    yield node

        for function in unique_functions(self.compilation_unit):
            for expr in function.all_expressions:
                yield from emit(expr)
            # Numeric constants modeled out of inline-assembly Yul bodies
            # are not expression Literals but carry the same readability
            # hazard (``r := or(r, 0x00000101...)``).
            for node in function.nodes:
                if node.kind != NodeKind.ASSEMBLY:
                    continue
                for op in node.ir_operations:
                    for var in op.read or []:
                        if isinstance(var, Constant) and id(var) not in seen:
                            seen.add(id(var))
                            yield var
        for contract in self.compilation_unit.contracts_derived:
            for variable in contract.state_variables_ordered:
                if variable.expression_initial is not None:
                    yield from emit(variable.expression_initial)

    @staticmethod
    def _digit_count(text: str) -> int:
        """Significant digit count of a bare numeric literal (0 when exempt).

        Anything that is not a bare run of digits is exempt: scientific
        notation (``e``), digit separators (``_``), decimals (``.``), and
        unit-suffixed forms all retain non-digit characters (a suffixed
        literal such as ``100 ether`` keeps only its short digit part, so
        it is naturally below the threshold).  Bare hex runs count their
        hex digits against the hex threshold.
        """
        if text.isdigit():
            return len(text) if len(text) > MAX_DIGITS else 0
        if text[:2].lower() == "0x":
            digits = text[2:]
            if digits and all(c in "0123456789abcdefABCDEF" for c in digits):
                return len(digits) if len(digits) > MAX_HEX_DIGITS else 0
        return 0

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for literal in self._literals():
            text = str(literal.value).strip()
            count = self._digit_count(text)
            if not count:
                continue
            results.append(
                self.finding(
                    [
                        literal,
                        " is a ",
                        str(count),
                        "-digit literal that is hard to read; use a suffix, "
                        "scientific notation, or digit separators",
                    ],
                    additional_fields={"digit_count": count},
                )
            )
        return results
