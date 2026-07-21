"""`incorrect-return` detector (spec/detectors-catalog.md §7.10 — normative).

Flags the assembly ``return(offset, size)`` opcode inside an *internal*
function that is invoked from other functions.  ``return`` halts the entire
EVM call frame and returns raw bytes to the external caller — it does not
return to the Solidity call site — so any calling function's remaining
logic is silently skipped and its declared returns are garbage.

Assembly blocks are opaque in the IR (spec/architecture.md §6), so the raw
source span of each assembly node is scanned (comments stripped), like the
``incorrect-shift`` detector does.  Original clean-room implementation.
"""

from __future__ import annotations

import re
from typing import Any

from velvet.core.function import FunctionLike
from velvet.detectors._batch_e_utils import unique_functions
from velvet.detectors._batch_g_utils import (
    assembly_block_sources,
    internal_callers,
    strip_comments_and_strings,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import InternalCall

_RETURN_RE = re.compile(r"\breturn\s*\(")


def assembly_has_return(source: str) -> bool:
    """True when an assembly block's source contains a ``return(...)``."""
    return bool(_RETURN_RE.search(strip_comments_and_strings(source)))


def _called_internally(unit: Any) -> set[int]:
    """``id()`` set of functions that are targets of internal calls."""
    called: set[int] = set()
    for function in unit.functions_and_modifiers:
        for op in function.all_ir_operations:
            if isinstance(op, InternalCall) and op.function is not None:
                called.add(id(op.function))
    return called


class IncorrectReturn(Detector):
    """Detect assembly return inside internally-called functions."""

    RULE = "incorrect-return"
    TITLE = "Assembly return inside an internal function"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#incorrect-return",
        title="Assembly return halts the whole call frame",
        description=(
            "An assembly return(offset, size) appears in an internal "
            "function invoked from other functions. return halts the whole "
            "EVM call frame instead of returning to the Solidity call "
            "site, so the caller's remaining logic is silently skipped."
        ),
        exploit_scenario=(
            "check(a) calls the internal _size(a), whose assembly ends "
            "with return(0, 32); the whole transaction returns 32 zero "
            "bytes and check's `s > 0` logic never executes."
        ),
        recommendation=(
            "Use leave (Yul) or normal Solidity returns to exit an "
            "internal function; reserve assembly return for the outermost "
            "dispatch."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        called = _called_internally(self.compilation_unit)
        for function in unique_functions(self.compilation_unit):
            if id(function) not in called:
                # Never invoked internally: it is the outermost execution
                # context, where assembly return is legitimate.
                continue
            for node, content in assembly_block_sources(function):
                if not assembly_has_return(content):
                    continue
                callers: list[FunctionLike] = internal_callers(
                    self.compilation_unit, function
                )
                caller_names = ", ".join(f.canonical_name for f in callers)
                results.append(
                    self.finding(
                        [
                            node,
                            " uses assembly return in the internal function ",
                            function,
                            f" (called from {caller_names}); the whole call "
                            "frame halts instead of returning to the caller",
                        ]
                    )
                )
        return results
