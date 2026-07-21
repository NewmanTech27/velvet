"""``inheritance-graph`` printer — Graphviz export of the inheritance DAG.

Spec: spec/printers-and-tools.md §A.3.  One ``.dot`` file per compilation
unit with one record node per contract (name, public functions, state
variables) and directed edges from each derived contract to its immediate
bases, labelled with the 1-based inheritance declaration order.

Visual indicators:
- functions overriding a parent's function: orange,
- functions colliding through multiple inheritance: grey note row,
- state variables shadowing a parent's variable: red,
- variables of contract type: referenced contract name in blue parentheses.

Original clean-room implementation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from velvet.core.contract import Contract
from velvet.core.types import UserDefinedType
from velvet.printers._utils import dot_quote, function_label, html_escape
from velvet.printers.base import Printer

_ORANGE = "#e68a00"
_GREY = "#888888"
_RED = "#cc0000"
_BLUE = "#0044cc"


def _public_function_row(contract: Contract, function: Any) -> str:
    label = html_escape(function_label(function))
    if function in contract.functions_shadowed:
        return f'<FONT COLOR="{_ORANGE}">{label}</FONT>'
    return label


def _variable_row(contract: Contract, variable: Any) -> str:
    text = f"{variable.type} {variable.name}"
    row = html_escape(text)
    if isinstance(variable.type, UserDefinedType) and isinstance(
        variable.type.type, Contract
    ):
        row += f' <FONT COLOR="{_BLUE}">({html_escape(variable.type.type.name)})</FONT>'
    if variable in contract.state_variables_shadowed:
        row = f'<FONT COLOR="{_RED}">{row}</FONT>'
    return row


def _collision_notes(contract: Contract) -> list[str]:
    """Signatures reachable via >= 2 direct bases but not overridden here."""
    own = {f.signature for f in contract.functions}
    providers: dict[str, list[str]] = {}
    for base in contract.direct_bases:
        for function in base.available_functions_from_inheritances():
            if function.signature in own or function.visibility == "private":
                continue
            providers.setdefault(function.signature, [])
            if base.name not in providers[function.signature]:
                providers[function.signature].append(base.name)
    notes = []
    for signature, bases in sorted(providers.items()):
        if len(bases) >= 2:
            notes.append(f"Collision: {signature} ({', '.join(bases)})")
    return notes


def _contract_node(contract: Contract) -> str:
    rows = []
    header = html_escape(contract.name)
    if contract.kind.value != "contract":
        header += f" &lt;&lt;{contract.kind.value}&gt;&gt;"
    rows.append(f'<TR><TD><B>{header}</B></TD></TR>')
    for function in contract.functions:
        if function.visibility in ("public", "external"):
            rows.append(
                f'<TR><TD ALIGN="LEFT">{_public_function_row(contract, function)}</TD></TR>'
            )
    for variable in contract.state_variables:
        rows.append(
            f'<TR><TD ALIGN="LEFT">{_variable_row(contract, variable)}</TD></TR>'
        )
    for note in _collision_notes(contract):
        rows.append(
            f'<TR><TD ALIGN="LEFT"><FONT COLOR="{_GREY}">{html_escape(note)}</FONT></TD></TR>'
        )
    table = '<TABLE BORDER="1" CELLBORDER="1" CELLSPACING="0">' + "".join(rows) + "</TABLE>"
    return f'  "{dot_quote(contract.name)}" [shape=plain, label=<{table}>];'


class InheritanceGraphPrinter(Printer):
    RULE = "inheritance-graph"
    TITLE = "Inheritance graph of the codebase (Graphviz .dot)"

    def output(self) -> None:
        unit = self.compilation_unit
        lines = ['digraph "inheritance-graph" {']
        for contract in unit.contracts:
            lines.append(_contract_node(contract))
        for contract in unit.contracts:
            for index, base in enumerate(contract.direct_bases, start=1):
                lines.append(
                    f'  "{dot_quote(contract.name)}" -> "{dot_quote(base.name)}"'
                    f' [label="{index}"];'
                )
        lines.append("}")
        lines.append("")
        filename = self._default_filename(unit)
        path = self.emit_file(filename, "\n".join(lines))
        self.info(f"Inheritance Graph: {path}")

    @staticmethod
    def _default_filename(unit: Any) -> str:
        for info in unit.compilation.source_units.values():
            stem = Path(info.filename.short).stem
            if stem:
                return f"{stem}.inheritance-graph.dot"
        return "inheritance-graph.dot"
