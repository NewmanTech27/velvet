"""``cfg`` printer — Graphviz export of every function's control-flow graph.

Spec: spec/printers-and-tools.md §A.5.  One ``.dot`` file per function
(all functions of all contracts, including modifiers and constructors):
one node per basic block labelled with the node kind and source expression,
directed edges for the control flow.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.printers._utils import dot_quote, sanitize_filename
from velvet.printers.base import Printer


def _node_label(node: Any) -> str:
    label = f"{node.node_id}: {node.kind.name}"
    if node.expression is not None:
        label += f"\n{node.expression}"
    return label


def render_function_cfg(function: Any) -> str:
    """Render one function's CFG as a digraph."""
    title = function.canonical_name
    lines = [f'digraph "{dot_quote(title)}" {{']
    lines.append('  node [shape=box];')
    for node in function.nodes:
        lines.append(f'  "{node.node_id}" [label="{dot_quote(_node_label(node))}"];')
    for node in function.nodes:
        for successor in node.successors:
            lines.append(f'  "{node.node_id}" -> "{successor.node_id}";')
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


class CfgPrinter(Printer):
    RULE = "cfg"
    TITLE = "Control-flow graph of every function (Graphviz .dot)"

    def output(self) -> None:
        for function in self.compilation_unit.functions_and_modifiers:
            if not function.is_implemented or not function.nodes:
                continue
            content = render_function_cfg(function)
            filename = sanitize_filename(f"{function.canonical_name}.cfg.dot")
            path = self.emit_file(filename, content)
            self.info(f"CFG: {path}")
