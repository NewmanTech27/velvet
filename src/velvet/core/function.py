"""Function and modifier model. Original clean-room implementation
(spec/architecture.md §4.3, api-surface.md §3.3)."""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING, Any, Iterator, Optional

from velvet.core.cfg_node import CFGNode, NodeKind
from velvet.core.source_mapping import SourceMapping
from velvet.core.variables import LocalVariable

if TYPE_CHECKING:
    from velvet.core.contract import Contract
    from velvet.core.expressions import Expression


class FunctionKind(enum.Enum):
    NORMAL = "normal"
    CONSTRUCTOR = "constructor"
    FALLBACK = "fallback"
    RECEIVE = "receive"


class FunctionLike(SourceMapping):
    """Shared base for Function and Modifier."""

    def __init__(self) -> None:
        super().__init__()
        self.name: str = ""
        self.visibility: str = "internal"
        self.payable: bool = False
        self.view: bool = False
        self.pure: bool = False
        self.virtual: bool = False
        self.is_implemented: bool = False
        self.contains_assembly: bool = False
        self.contract: Optional[Contract] = None
        self.contract_declarer: Optional[Contract] = None
        self.parameters: list[LocalVariable] = []
        self.returns: list[LocalVariable] = []
        self.modifiers: list[Modifier] = []
        self.explicit_base_constructor_calls: list[Contract] = []
        self._entry_point: Optional[CFGNode] = None
        self._nodes: list[CFGNode] = []
        self.overrides: list[FunctionLike] = []  # functions/modifiers this one overrides
        self.overridden_by: list[FunctionLike] = []
        # Locals synthesized by the CFG builder (e.g. ternary-lowering temps).
        # They behave like declared locals for scoping/IR purposes.
        self.synthesized_locals: list[LocalVariable] = []

    # ------------------------------------------------------------- identity
    @property
    def kind(self) -> FunctionKind:
        return FunctionKind.NORMAL

    @property
    def canonical_name(self) -> str:
        cname = self.contract_declarer.name if self.contract_declarer else "?"
        return f"{cname}.{self.signature}"

    @property
    def signature(self) -> str:
        """`name(type1,type2)` with canonical types."""
        params = ",".join(str(p.type) for p in self.parameters)
        return f"{self.name}({params})"

    @property
    def full_name(self) -> str:
        """Signature including return types."""
        returns = ",".join(str(r.type) for r in self.returns)
        base = f"{self.signature}"
        if returns:
            return f"{base} returns({returns})"
        return base

    @property
    def solidity_signature(self) -> str:
        return self.signature

    @property
    def is_constructor(self) -> bool:
        return self.kind == FunctionKind.CONSTRUCTOR

    @property
    def is_empty(self) -> bool:
        return self.is_implemented and not any(
            n.expression is not None for n in self._nodes
        )

    @property
    def is_shadowed(self) -> bool:
        return False  # refined by contract-level shadowing analysis

    # ------------------------------------------------------------------ CFG
    @property
    def entry_point(self) -> Optional[CFGNode]:
        return self._entry_point

    @property
    def nodes(self) -> list[CFGNode]:
        return self._nodes

    def add_node(self, node: CFGNode) -> CFGNode:
        node.node_id = len(self._nodes)
        node.function = self  # type: ignore[assignment]
        self._nodes.append(node)
        if self._entry_point is None:
            self._entry_point = node
        return node

    @property
    def all_expressions(self) -> list[Expression]:
        return [n.expression for n in self._nodes if n.expression is not None]

    @property
    def all_nodes(self) -> list[CFGNode]:
        """Own nodes plus the nodes of applied modifiers."""
        result = list(self._nodes)
        for mod in self.modifiers:
            result.extend(mod.nodes)
        return result

    @property
    def all_ir_operations(self) -> list[Any]:
        ops: list[Any] = []
        for node in self.all_nodes:
            ops.extend(node.ir_operations)
        return ops

    # ----------------------------------------------------- derived analyses
    # Read/write sets, call decomposition, dependency and reachability are
    # computed by velvet.analyses (spec/architecture.md §7); these accessors
    # compute lazily on first use and cache.
    @property
    def cyclomatic_complexity(self) -> int:
        """E - N + 2P over the function's CFG."""
        nodes = self._nodes
        edges = sum(len(n.successors) for n in nodes)
        return edges - len(nodes) + 2 if nodes else 1

    def _rw(self) -> Any:
        cached = getattr(self, "_rw_cache", None)
        if cached is None:
            from velvet.analyses.read_write import function_read_write

            cached = function_read_write(self)
            self._rw_cache = cached
        return cached

    @property
    def variables_read(self) -> list[Any]:
        return self._rw().variables_read

    @property
    def variables_written(self) -> list[Any]:
        return self._rw().variables_written

    @property
    def state_variables_read(self) -> list[Any]:
        return self._rw().state_variables_read

    @property
    def state_variables_written(self) -> list[Any]:
        return self._rw().state_variables_written

    @property
    def local_variables_read(self) -> list[Any]:
        return self._rw().local_variables_read

    @property
    def local_variables_written(self) -> list[Any]:
        return self._rw().local_variables_written

    @property
    def state_variables_read_deep(self) -> list[Any]:
        """Transitive state-var reads across internal calls (fixpoint)."""
        from velvet.analyses.read_write import deep_state_variables

        return deep_state_variables(self, read=True)

    @property
    def state_variables_written_deep(self) -> list[Any]:
        """Transitive state-var writes across internal calls (fixpoint)."""
        from velvet.analyses.read_write import deep_state_variables

        return deep_state_variables(self, read=False)

    # -------------------------------------------------------- call access
    def _calls_of(self, kinds: tuple[type, ...]) -> list[Any]:
        return [
            op
            for node in self.all_nodes
            for op in node.ir_operations
            if isinstance(op, kinds)
        ]

    @property
    def internal_calls(self) -> list[Any]:
        from velvet.ir.operations import InternalCall

        return self._calls_of((InternalCall,))

    @property
    def high_level_calls(self) -> list[Any]:
        from velvet.ir.operations import HighLevelCall, LibraryCall

        return [
            op
            for op in self._calls_of((HighLevelCall,))
            if not isinstance(op, LibraryCall)
        ]

    @property
    def low_level_calls(self) -> list[Any]:
        from velvet.ir.operations import LowLevelCall

        return self._calls_of((LowLevelCall,))

    @property
    def library_calls(self) -> list[Any]:
        from velvet.ir.operations import LibraryCall

        return self._calls_of((LibraryCall,))

    @property
    def solidity_calls(self) -> list[Any]:
        from velvet.ir.operations import SolidityCall

        return self._calls_of((SolidityCall,))

    @property
    def event_calls(self) -> list[Any]:
        from velvet.ir.operations import EventCall

        return self._calls_of((EventCall,))

    @property
    def all_ir_operations_ssa(self) -> list[Any]:
        ops: list[Any] = []
        for node in self.all_nodes:
            ops.extend(node.ir_operations_ssa)
        return ops

    @property
    def all_internal_calls_reachable(self) -> list[Any]:
        """Transitive internal call targets (cycle-safe)."""
        from velvet.analyses.reachability import internal_calls_reachable

        return internal_calls_reachable(self)

    # ------------------------------------------------------- auth/reachability
    @property
    def is_protected(self) -> bool:
        """Protected-function heuristic (spec/architecture.md §7.2)."""
        from velvet.analyses.protected import is_protected

        return is_protected(self)

    def is_reachable_from(self, entry: FunctionLike) -> bool:
        """True when ``entry`` can reach this function over the call graph."""
        from velvet.analyses.reachability import is_reachable_from

        return is_reachable_from(entry, self)

    @property
    def entry_points_reaching_this(self) -> list[Any]:
        from velvet.analyses.reachability import entry_points_reaching

        return entry_points_reaching(self)

    def __str__(self) -> str:
        return self.canonical_name

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.canonical_name})"


class Function(FunctionLike):
    def __init__(self) -> None:
        super().__init__()
        self._kind = FunctionKind.NORMAL

    @property
    def kind(self) -> FunctionKind:
        return self._kind

    def set_kind(self, kind: FunctionKind) -> None:
        self._kind = kind


class Modifier(FunctionLike):
    """A modifier declaration (function-like, has a body and CFG)."""

    @property
    def signature(self) -> str:
        params = ",".join(str(p.type) for p in self.parameters)
        return f"{self.name}({params})"
