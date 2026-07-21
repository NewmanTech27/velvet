"""`deprecated-standards` detector (spec/detectors-catalog.md §8.5 —
normative).

Flags usage of Solidity constructs removed or deprecated by the language:
``throw``, ``constant`` (as a function modifier), ``sha3``, ``suicide``,
``callcode``, ``msg.gas``, ``block.blockhash``, ``now``, ``var``,
``years``, ...

Detection is two-pronged, per the catalog's "lexical/AST presence" contract:

- **AST/IR level** (precise, node-located): ``now`` reads, ``suicide(...)``
  builtin calls, ``.callcode(...)`` low-level calls, the legacy ``throw``
  statement (modern ``revert CustomError(...)`` nodes, which share the
  same CFG node kind, are *not* flagged — they are valid Solidity), and
  the ``constant`` function modifier (spotted in the declaration header of
  view/pure functions).
- **Lexical level** (source-text scan with comments and string literals
  blanked): constructs that predate the ASTs velvet can parse —
  ``sha3(``, ``msg.gas``, ``block.blockhash(``, ``var`` declarations and
  the ``years`` time unit.  These cannot appear in code compiled by a
  modern solc; the scan keeps the full deprecated list enforced for legacy
  sources.

Original clean-room implementation.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

from velvet.core.cfg_node import NodeKind
from velvet.core.variables import SolidityVariable
from velvet.detectors._batch_g_utils import strip_comments_and_strings
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import LowLevelCall, SolidityCall

#: Lexical deprecated constructs: (name, pattern, modern replacement).
#: Only constructs without AST/IR coverage are scanned lexically (they
#: predate the compilers velvet can parse, so they have no IR shape).
LEXICAL_DEPRECATED: tuple[tuple[str, "re.Pattern[str]", str], ...] = (
    ("sha3", re.compile(r"\bsha3\s*\("), "keccak256"),
    ("msg.gas", re.compile(r"\bmsg\.gas\b"), "gasleft()"),
    ("block.blockhash", re.compile(r"\bblock\.blockhash\s*\("), "blockhash()"),
    ("var", re.compile(r"\bvar\s+[A-Za-z_$]"), "an explicit type declaration"),
    ("years", re.compile(r"\d\s+years\b"), "an explicit seconds constant"),
)

_CONSTANT_MODIFIER_RE = re.compile(r"\bconstant\b")


def _is_legacy_throw(node: Any) -> bool:
    """True only for the deprecated legacy ``throw;`` statement.

    Velvet maps both the legacy ``throw;`` (solc < 0.5) and the modern
    ``revert CustomError(...)`` (a perfectly valid construct) onto
    ``NodeKind.THROW`` because both abort the transaction. Only the
    former is deprecated. The legacy statement's source text is exactly
    ``throw`` (optionally with a trailing semicolon) and it carries no
    error-call expression; a modern revert names an error (its source
    starts with ``revert``) or, programmatically, carries the call.
    """
    content = ""
    mapping = getattr(node, "source_mapping", None)
    if mapping is not None and mapping.content:
        content = mapping.content
    if content:
        return content.strip().rstrip(";").strip() == "throw"
    # No source text (programmatic model): a bare THROW node without an
    # error-call expression is the legacy statement.
    return getattr(node, "expression", None) is None


def find_deprecated_lexemes(source: str) -> list[tuple[str, str]]:
    """Deprecated constructs present in ``source`` as ``(name, replacement)``.

    Comments and string literals are blanked before matching.  Each
    construct is reported once, in first-occurrence order.
    """
    text = strip_comments_and_strings(source)
    found: list[tuple[str, str]] = []
    for name, pattern, replacement in LEXICAL_DEPRECATED:
        if pattern.search(text):
            found.append((name, replacement))
    return found


def _declares_constant_modifier(function: Any) -> bool:
    """True when a view/pure function's declaration header uses ``constant``."""
    if not (function.view or function.pure):
        return False
    mapping = function.source_mapping
    content = mapping.content if mapping is not None else ""
    if not content:
        return False
    header = content.split("{", 1)[0]
    return bool(_CONSTANT_MODIFIER_RE.search(header))


class DeprecatedStandards(Detector):
    """Detect usage of deprecated/removed Solidity constructs."""

    RULE = "deprecated-standards"
    TITLE = "Deprecated Solidity constructs"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#deprecated-standards",
        title="Deprecated standards",
        description=(
            "The code uses constructs that are deprecated or removed from "
            "Solidity (throw, constant as a function modifier, sha3, "
            "suicide, callcode, msg.gas, block.blockhash, now, var, "
            "years). They break compilation on modern compilers and hide "
            "well-known footguns."
        ),
        exploit_scenario=(
            "A legacy contract h() is declared constant and returns now; "
            "ported as-is to a modern codebase it fails to compile, and "
            "its block.timestamp dependence goes unnoticed."
        ),
        recommendation=(
            "Replace each deprecated construct with its modern equivalent "
            "(revert(), view, keccak256, selfdestruct, delegatecall, "
            "gasleft(), blockhash(), block.timestamp)."
        ),
    )

    # ------------------------------------------------------------- AST/IR
    def _ast_findings(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts:
            for function in contract.functions_and_modifiers:
                if _declares_constant_modifier(function):
                    results.append(
                        self.finding(
                            [
                                function,
                                " is declared with the deprecated constant "
                                "modifier; use view/pure",
                            ]
                        )
                    )
                seen_kinds: set[str] = set()
                for node in function.nodes:
                    if (
                        node.kind is NodeKind.THROW
                        and _is_legacy_throw(node)
                        and "throw" not in seen_kinds
                    ):
                        seen_kinds.add("throw")
                        results.append(
                            self.finding(
                                [node, " uses throw in ", function, "; use revert()"]
                            )
                        )
                        continue
                    for op in node.ir_operations:
                        if (
                            isinstance(op, SolidityCall)
                            and op.function.name == "suicide"
                            and "suicide" not in seen_kinds
                        ):
                            seen_kinds.add("suicide")
                            results.append(
                                self.finding(
                                    [
                                        node,
                                        " uses suicide in ",
                                        function,
                                        "; use selfdestruct",
                                    ]
                                )
                            )
                        elif (
                            isinstance(op, LowLevelCall)
                            and op.function_name == "callcode"
                            and "callcode" not in seen_kinds
                        ):
                            seen_kinds.add("callcode")
                            results.append(
                                self.finding(
                                    [
                                        node,
                                        " uses callcode in ",
                                        function,
                                        "; use delegatecall",
                                    ]
                                )
                            )
                        elif (
                            any(
                                isinstance(var, SolidityVariable) and var.name == "now"
                                for var in op.read
                            )
                            and "now" not in seen_kinds
                        ):
                            seen_kinds.add("now")
                            results.append(
                                self.finding(
                                    [
                                        node,
                                        " uses now in ",
                                        function,
                                        "; use block.timestamp",
                                    ]
                                )
                            )
        return results

    # ------------------------------------------------------------- lexical
    def _contracts_in_unit(self, info: Any) -> list[Any]:
        return [
            c
            for c in self.compilation_unit.contracts
            if c.source_mapping is not None
            and c.source_mapping.filename is not None
            and c.source_mapping.filename.absolute == info.filename.absolute
        ]

    def _lexical_findings(self) -> list[Finding]:
        results: list[Finding] = []
        artifacts = self.compilation_unit.compilation
        source_units: Iterator[Any] = iter(artifacts.source_units.values())
        for info in source_units:
            found = find_deprecated_lexemes(info.source)
            if not found:
                continue
            summary = ", ".join(f"{name} (use {replacement})" for name, replacement in found)
            contracts = self._contracts_in_unit(info)
            if not contracts:
                results.append(
                    self.finding(
                        [
                            f"Source unit {info.filename.used} uses deprecated "
                            f"Solidity constructs: {summary}",
                        ]
                    )
                )
                continue
            for contract in contracts:
                results.append(
                    self.finding(
                        [
                            contract,
                            " uses deprecated Solidity constructs: ",
                            summary,
                        ]
                    )
                )
        return results

    def analyze(self) -> list[Finding]:
        return self._ast_findings() + self._lexical_findings()
