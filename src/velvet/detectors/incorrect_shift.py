"""`incorrect-shift` detector (spec/detectors-catalog.md §7.3 — normative).

In Yul, ``shl``/``shr``/``sar`` take the shift *amount* as the first operand
and the *value* as the second — the reverse of the Solidity ``<<``/``>>``
operators and of developer intuition.  Flag assembly calls whose operand
order indicates a swap: a non-literal first operand (the value) followed by
a numeric-literal second operand (obviously the intended shift amount).

Assembly blocks are opaque in the IR (spec/architecture.md §6), so the raw
source span of each assembly node is scanned with a small balanced-paren
argument splitter.  Original clean-room implementation.
"""

from __future__ import annotations

import re
from typing import Optional

from velvet.core.cfg_node import NodeKind
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

_SHIFT_RE = re.compile(r"\b(shl|shr|sar)\s*\(")
_NUMERIC_RE = re.compile(r"^(0x[0-9a-fA-F]+|[0-9]+)$")
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)


def _is_numeric_literal(text: str) -> bool:
    return bool(_NUMERIC_RE.match(text.strip()))


def _split_call_args(source: str, open_paren: int) -> Optional[list[str]]:
    """Split a ``f(arg0, arg1)`` call starting at ``open_paren``.

    Returns the top-level argument strings, or None when the parenthesis is
    unbalanced.
    """
    depth = 0
    args: list[str] = []
    current: list[str] = []
    for char in source[open_paren:]:
        if char == "(":
            depth += 1
            if depth > 1:
                current.append(char)
            continue
        if char == ")":
            depth -= 1
            if depth == 0:
                args.append("".join(current))
                return args
            current.append(char)
            continue
        if char == "," and depth == 1:
            args.append("".join(current))
            current = []
            continue
        current.append(char)
    return None


def find_reversed_shifts(source: str) -> list[tuple[str, str, str]]:
    """``(mnemonic, first, second)`` for shift calls with swapped operands."""
    text = _BLOCK_COMMENT_RE.sub("", _LINE_COMMENT_RE.sub("", source))
    results: list[tuple[str, str, str]] = []
    for match in _SHIFT_RE.finditer(text):
        args = _split_call_args(text, match.end() - 1)
        if args is None or len(args) != 2:
            continue
        first, second = args[0].strip(), args[1].strip()
        # Yul order is (amount, value): a literal second operand with a
        # non-literal first means the two are almost certainly swapped.
        if _is_numeric_literal(second) and not _is_numeric_literal(first):
            results.append((match.group(1), first, second))
    return results


class IncorrectShift(Detector):
    """Detect shl/shr/sar assembly calls with swapped operands."""

    RULE = "incorrect-shift"
    TITLE = "Shift in inline assembly with swapped operands"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#incorrect-shift",
        title="Shift in inline assembly with swapped operands",
        description=(
            "Yul shift builtins shl/shr/sar take the shift amount first and "
            "the value second — the reverse of the Solidity operators. "
            "Passing the value first and a constant amount second silently "
            "computes the wrong result."
        ),
        exploit_scenario=(
            "lowByte(word) runs assembly { r := shr(word, 248) } intending "
            "to extract the top byte; the operands are swapped so r ends up "
            "as word >> word instead of word >> 248."
        ),
        recommendation=(
            "Swap the operands: shl(amount, value) / shr(amount, value) / "
            "sar(amount, value)."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts:
            for function in contract.functions_and_modifiers:
                for node in function.nodes:
                    if node.kind is not NodeKind.ASSEMBLY:
                        continue
                    mapping = node.source_mapping
                    content = mapping.content if mapping is not None else ""
                    if not content:
                        continue
                    for mnemonic, first, second in find_reversed_shifts(content):
                        results.append(
                            self.finding(
                                [
                                    node,
                                    f" uses {mnemonic}({first}, {second}) "
                                    "with the shift amount as the second "
                                    "operand; Yul expects (amount, value) "
                                    "in ",
                                    function,
                                ]
                            )
                        )
        return results
