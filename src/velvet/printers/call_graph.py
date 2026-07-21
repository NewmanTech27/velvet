"""``call-graph`` printer — Graphviz export of the function call graph.

Spec: spec/printers-and-tools.md §A.4.  One ``.dot`` file per contract:
ellipse node per function grouped into one cluster (box) per contract,
directed caller -> callee edges for internal, cross-contract and library
calls; calls to Solidity built-ins are grouped in a synthetic ``[Solidity]``
cluster.  Unresolvable destinations land in an ``External`` cluster.

Original clean-room implementation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from velvet.core.function import FunctionKind
from velvet.ir.operations import (
    HighLevelCall,
    InternalCall,
    LowLevelCall,
    NewContract,
    Send,
    SolidityCall,
    Transfer,
)
from velvet.printers._utils import dot_quote, function_label, value_name
from velvet.printers.base import Printer

_SOLIDITY_CLUSTER = "[Solidity]"
_EXTERNAL_CLUSTER = "External"


class _CallGraphBuilder:
    """Collects nodes/clusters/edges for one contract's call graph."""

    def __init__(self, contract: Any) -> None:
        self.contract = contract
        # cluster label -> {node_id: node_label}
        self.clusters: dict[str, dict[str, str]] = {}
        self.edges: list[tuple[str, str]] = []
        self._edge_set: set[tuple[str, str]] = set()

    # ---------------------------------------------------------------- nodes
    def add_node(self, cluster: str, node_id: str, label: str) -> None:
        self.clusters.setdefault(cluster, {}).setdefault(node_id, label)

    def add_edge(self, src: str, dst: str) -> None:
        if (src, dst) not in self._edge_set and src != dst:
            self._edge_set.add((src, dst))
            self.edges.append((src, dst))

    # ------------------------------------------------------------- building
    def _function_node(self, function: Any) -> str:
        declarer = function.contract_declarer or function.contract
        cluster = declarer.name if declarer is not None else _EXTERNAL_CLUSTER
        node_id = function.canonical_name
        self.add_node(cluster, node_id, function_label(function))
        return node_id

    def _resolved_callee(self, op: Any) -> Optional[str]:
        target = getattr(op, "function", None)
        if target is None:
            return None
        return self._function_node(target)

    def _external_node(self, label: str) -> str:
        node_id = f"{_EXTERNAL_CLUSTER}:{label}"
        self.add_node(_EXTERNAL_CLUSTER, node_id, label)
        return node_id

    def _solidity_node(self, name: str) -> str:
        node_id = f"{_SOLIDITY_CLUSTER}:{name}"
        self.add_node(_SOLIDITY_CLUSTER, node_id, name)
        return node_id

    def build(self) -> None:
        own_functions = list(self.contract.functions)
        for function in own_functions:
            self._function_node(function)
        for function in own_functions:
            caller = function.canonical_name
            for node in function.all_nodes:
                for op in node.ir_operations:
                    self._handle_op(caller, op)

    def _handle_op(self, caller: str, op: Any) -> None:
        if isinstance(op, InternalCall):
            callee = self._resolved_callee(op)
            if callee is not None:
                self.add_edge(caller, callee)
            # internal dynamic calls have no resolvable target: omitted
        elif isinstance(op, HighLevelCall):  # includes LibraryCall
            callee = self._resolved_callee(op)
            if callee is None:
                label = f"{value_name(op.destination)}.{op.function_name}"
                callee = self._external_node(label)
            self.add_edge(caller, callee)
        elif isinstance(op, LowLevelCall):
            label = f"{value_name(op.destination)}.{op.function_name}"
            self.add_edge(caller, self._external_node(label))
        elif isinstance(op, SolidityCall):
            self.add_edge(caller, self._solidity_node(op.function.name))
        elif isinstance(op, (Send, Transfer)):
            name = "send" if isinstance(op, Send) else "transfer"
            self.add_edge(caller, self._solidity_node(name))
        elif isinstance(op, NewContract):
            constructor = self._constructor_of(op.contract)
            if constructor is not None:
                self.add_edge(caller, self._function_node(constructor))
            else:
                self._function_node_stub(op.contract, caller)

    @staticmethod
    def _constructor_of(contract: Any) -> Optional[Any]:
        if contract is None:
            return None
        for function in getattr(contract, "functions", []):
            if function.kind == FunctionKind.CONSTRUCTOR:
                return function
        return None

    def _function_node_stub(self, contract: Any, caller: str) -> None:
        name = getattr(contract, "name", str(contract))
        node_id = f"{name}.constructor"
        self.add_node(name, node_id, "constructor")
        self.add_edge(caller, node_id)

    # -------------------------------------------------------------- rendering
    def render(self) -> str:
        lines = [f'digraph "{dot_quote(self.contract.name)}.call-graph" {{']
        lines.append('  node [shape=ellipse];')
        for index, (cluster, nodes) in enumerate(self.clusters.items()):
            lines.append(f'  subgraph cluster_{index} {{')
            lines.append(f'    label="{dot_quote(cluster)}";')
            for node_id, label in nodes.items():
                lines.append(
                    f'    "{dot_quote(node_id)}" [label="{dot_quote(label)}"];'
                )
            lines.append("  }")
        for src, dst in self.edges:
            lines.append(f'  "{dot_quote(src)}" -> "{dot_quote(dst)}";')
        lines.append("}")
        lines.append("")
        return "\n".join(lines)


class CallGraphPrinter(Printer):
    RULE = "call-graph"
    TITLE = "Call graph of the contracts (Graphviz .dot, one file per contract)"

    def output(self) -> None:
        for contract in self.compilation_unit.contracts:
            if not contract.functions:
                continue
            builder = _CallGraphBuilder(contract)
            builder.build()
            filename = f"{self._file_stem(contract)}.{contract.name}.call-graph.dot"
            path = self.emit_file(filename, builder.render())
            self.info(f"Call Graph: {path}")

    @staticmethod
    def _file_stem(contract: Any) -> str:
        filename = contract.source_mapping.filename
        if filename is not None and filename.short:
            return Path(filename.short).name
        return "unknown"
