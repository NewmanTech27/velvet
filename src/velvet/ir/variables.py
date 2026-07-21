"""IR-synthesized variables (spec/architecture.md §6.2).

These variables never appear in source; they are materialized by the IR
conversion to hold sub-expression results (``TemporaryVariable``),
dereference results (``ReferenceVariable``) and multi-return values
(``TupleVariable``).  Counters are scoped per function so names stay
deterministic (``TMP_0``, ``REF_0``, ``TUPLE_0``, ...).

Original clean-room implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from velvet.core.variables import Variable

if TYPE_CHECKING:
    from velvet.core.function import FunctionLike


class IRVariable(Variable):
    """Base class for IR-synthesized variables."""

    def __init__(self, function: Optional[FunctionLike], index: int) -> None:
        super().__init__()
        self.function = function
        self.index = index  # per-kind, per-function counter
        # SSA bookkeeping (set by velvet.ir.ssa when this is an SSA version)
        self.non_ssa_version: Optional[Variable] = None

    @property
    def ssa_index(self) -> int:
        """SSA version number; 0 for non-SSA (plain IR) variables."""
        return int(getattr(self, "_ssa_index", 0))


class TemporaryVariable(IRVariable):
    """Holds the result of a sub-expression (``TMP_n``)."""

    def __init__(self, function: Optional[FunctionLike], index: int) -> None:
        super().__init__(function, index)
        self.name = f"TMP_{index}"


class ReferenceVariable(IRVariable):
    """Holds a dereference result (``REF_n``): indexing or member access.

    ``points_to`` is the base value the reference dereferences (a state or
    local variable, or another ``ReferenceVariable`` for chained access).
    """

    def __init__(
        self, function: Optional[FunctionLike], index: int, points_to: Any = None
    ) -> None:
        super().__init__(function, index)
        self.name = f"REF_{index}"
        self.points_to = points_to


class TupleVariable(IRVariable):
    """Holds a multi-value result (``TUPLE_n``), e.g. a multi-return call."""

    def __init__(self, function: Optional[FunctionLike], index: int) -> None:
        super().__init__(function, index)
        self.name = f"TUPLE_{index}"


def root_base(variable: Any) -> Any:
    """Resolve a ReferenceVariable chain to its ultimate base value."""
    seen: set[int] = set()
    current = variable
    while isinstance(current, ReferenceVariable) and id(current) not in seen:
        seen.add(id(current))
        current = current.points_to
    return current
