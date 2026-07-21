"""CFG node model. Original clean-room implementation (spec/architecture.md §5)."""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING, Any, Optional

from velvet.core.expressions import Expression
from velvet.core.source_mapping import SourceMapping

if TYPE_CHECKING:
    from velvet.core.function import Function
    from velvet.core.variables import LocalVariable, StateVariable, Variable


class NodeKind(enum.Enum):
    ENTRYPOINT = "ENTRYPOINT"
    EXPRESSION = "EXPRESSION"
    VARIABLE = "VARIABLE"
    IF = "IF"
    ENDIF = "ENDIF"
    START_LOOP = "START_LOOP"
    END_LOOP = "END_LOOP"
    IF_LOOP = "IF_LOOP"
    CONTINUE = "CONTINUE"
    BREAK = "BREAK"
    RETURN = "RETURN"
    THROW = "THROW"
    ASSEMBLY = "ASSEMBLY"
    END_ASSEMBLY = "END_ASSEMBLY"
    TRY = "TRY"
    CATCH = "CATCH"
    #: Modifier ``_`` statement: the point where the modified function's
    #: body (and any inner modifiers) is spliced in.  The node carries no
    #: expression and no IR; it exists so inter-procedural analyses can
    #: split a modifier body into the parts running before/after ``_``.
    PLACEHOLDER = "PLACEHOLDER"


class CFGNode(SourceMapping):
    """A control-flow graph vertex carrying at most one expression."""

    _next_id = 0

    def __init__(self, kind: NodeKind = NodeKind.EXPRESSION) -> None:
        super().__init__()
        self.kind = kind
        self.node_id: int = -1  # assigned by the owning function
        self.expression: Optional[Expression] = None
        self.variable_declaration: Optional[Variable] = None
        self.ir_operations: list[Any] = []  # IR ops (Wave 2)
        self.ir_operations_ssa: list[Any] = []  # SSA-view ops (Wave 2)
        self.function: Optional[Function] = None
        self._successors: list[CFGNode] = []
        self._predecessors: list[CFGNode] = []
        self._is_reachable = True

    # ------------------------------------------------------------------ edges
    @property
    def successors(self) -> list[CFGNode]:
        return self._successors

    @property
    def predecessors(self) -> list[CFGNode]:
        return self._predecessors

    def add_successor(self, node: CFGNode) -> None:
        if node not in self._successors:
            self._successors.append(node)
        if self not in node._predecessors:
            node._predecessors.append(self)

    def add_predecessor(self, node: CFGNode) -> None:
        node.add_successor(self)

    # ------------------------------------------------------------------ facts
    @property
    def is_reachable(self) -> bool:
        return self._is_reachable

    def set_reachable(self, value: bool) -> None:
        self._is_reachable = value

    @property
    def contains_if(self) -> bool:
        return self.kind in (NodeKind.IF, NodeKind.IF_LOOP)

    # ------------------------------------------------------- analysis sets
    # Read/write sets and CFG facts are computed by velvet.analyses
    # (spec/architecture.md §7) and consumed uniformly through these
    # properties; they are computed lazily on first access and cached.
    def _node_sets(self) -> Any:
        cached = getattr(self, "_rw_cache", None)
        if cached is None:
            from velvet.analyses.read_write import node_read_write

            cached = node_read_write(self)
            self._rw_cache = cached
        return cached

    @property
    def variables_read(self) -> list[Variable]:
        return self._node_sets().variables_read

    @property
    def variables_written(self) -> list[Variable]:
        return self._node_sets().variables_written

    @property
    def state_variables_read(self) -> list[StateVariable]:
        return self._node_sets().state_variables_read

    @property
    def state_variables_written(self) -> list[StateVariable]:
        return self._node_sets().state_variables_written

    @property
    def local_variables_read(self) -> list[LocalVariable]:
        return self._node_sets().local_variables_read

    @property
    def local_variables_written(self) -> list[LocalVariable]:
        return self._node_sets().local_variables_written

    @property
    def contract(self) -> Any:
        if self.function is None:
            return None
        return self.function.contract_declarer or self.function.contract

    @property
    def is_inside_loop(self) -> bool:
        """True when the node belongs to a natural loop (spec §5)."""
        cached = getattr(self, "_inside_loop", None)
        if cached is None:
            from velvet.analyses.reachability import compute_loop_membership

            assert self.function is not None
            compute_loop_membership(self.function)
            cached = getattr(self, "_inside_loop", False)
        return cached

    def __str__(self) -> str:
        if self.expression is not None:
            return f"{self.kind.name} {self.expression}"
        return self.kind.name

    def __repr__(self) -> str:
        return f"CFGNode(#{self.node_id} {self})"
