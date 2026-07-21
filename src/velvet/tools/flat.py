"""``velvet-flat`` — code flattener (spec/printers-and-tools.md §B.3).

Merges a multi-file Solidity codebase into standalone, compilable source by
textually inlining the import graph:

- source units are emitted in topological (imports-first) order;
- every source unit is emitted exactly once (dedup keyed on file path);
- ``import`` statements are stripped and ``pragma`` directives / SPDX license
  identifiers are merged into a single file preamble (solidity version
  constraints are AND-ed — whitespace-separated constraints intersect);
- circular imports are tolerated (cycle edges are broken; solc resolves
  declarations across the single flattened unit).

Strategies (§B.3.2): ``onefile`` (default; the whole codebase in one file) and
``most-derived`` (one standalone file per most-derived contract, written to
``--dir``). ``--contract NAME`` restricts one-file output to the source units
a contract needs (its own files, its ancestors' files and their transitive
imports).

Invocation: ``velvet-flat TARGET [-o output.sol]``.
Exit code: 0 = success, 2 = usage/compilation error.

Original clean-room implementation.
"""

from __future__ import annotations

import argparse
import posixpath
import sys
from pathlib import Path
from typing import Optional

from velvet.compile.artifacts import SourceUnitInfo
from velvet.core.contract import Contract
from velvet.exceptions import VelvetError
from velvet.session import Velvet
from velvet.tools.common import (
    SPDX_RE,
    build_session,
    find_contract,
    solidity_pragma_expression,
)

# ---------------------------------------------------------------------------
# source-unit graph
# ---------------------------------------------------------------------------


def _source_units(session: Velvet) -> dict[str, SourceUnitInfo]:
    """All source units of the session keyed by their compiler used-name."""
    units: dict[str, SourceUnitInfo] = {}
    for unit in session.compilation_units:
        for info in unit.compilation.source_units.values():
            units.setdefault(info.filename.used, info)
    return units


def _resolve_import(
    units: dict[str, SourceUnitInfo], importer: str, path: str
) -> Optional[str]:
    """Resolve an import path (as written) to a source-unit key."""
    norm = posixpath.normpath(path)
    if norm in units:
        return norm
    relative = posixpath.normpath(posixpath.join(posixpath.dirname(importer), path))
    if relative in units:
        return relative
    for key, info in units.items():
        absolute = info.filename.absolute.replace("\\", "/")
        if key.endswith("/" + norm) or absolute.endswith("/" + norm):
            return key
    return None  # external/dependency import not part of the compilation


def _import_graph(
    session: Velvet, units: dict[str, SourceUnitInfo]
) -> dict[str, list[str]]:
    """Map each source unit to the source units it imports (deduped)."""
    graph: dict[str, list[str]] = {key: [] for key in units}
    for unit in session.compilation_units:
        for directive in unit.imports:
            filename = directive.source_mapping.filename
            if filename is None or filename.used not in graph:
                continue
            target = _resolve_import(units, filename.used, directive.path)
            if target and target != filename.used and target not in graph[filename.used]:
                graph[filename.used].append(target)
    return graph


def _topo_order(keys: list[str], graph: dict[str, list[str]]) -> list[str]:
    """Dependencies-first ordering; cycle edges are broken deterministically."""
    order: list[str] = []
    visited: set[str] = set()
    on_stack: set[str] = set()

    def visit(key: str) -> None:
        if key in visited or key in on_stack:
            return
        on_stack.add(key)
        for dep in graph.get(key, []):
            visit(dep)
        on_stack.discard(key)
        visited.add(key)
        order.append(key)

    for key in sorted(keys):
        visit(key)
    return order


def _dependency_closure(roots: set[str], graph: dict[str, list[str]]) -> set[str]:
    closure: set[str] = set()
    stack = list(roots)
    while stack:
        key = stack.pop()
        if key in closure:
            continue
        closure.add(key)
        stack.extend(graph.get(key, []))
    return closure


def _contract_files(contract: Contract) -> set[str]:
    """Source-unit keys declaring the contract or any of its ancestors."""
    files: set[str] = set()
    for current in [contract] + list(contract.inheritance):
        filename = current.source_mapping.filename
        if filename is not None:
            files.add(filename.used)
    return files


# ---------------------------------------------------------------------------
# source stripping and preamble
# ---------------------------------------------------------------------------


def _directive_spans(session: Velvet, key: str) -> list[tuple[int, int]]:
    """(start, end) byte spans of all import/pragma directives of one file."""
    spans: list[tuple[int, int]] = []
    for unit in session.compilation_units:
        for directive in [*unit.imports, *unit.pragmas]:
            mapping = directive.source_mapping
            if mapping.filename is not None and mapping.filename.used == key:
                spans.append((mapping.start, mapping.start + mapping.length))
    return spans


def _strip_spans(source: str, spans: list[tuple[int, int]]) -> str:
    """Remove (start, end) spans from source text (overlap-safe)."""
    for start, end in sorted(spans, reverse=True):
        source = source[:start] + source[end:]
    return source


def _strip_source(session: Velvet, key: str, source: str) -> str:
    """Source body without imports, pragmas and SPDX license comments."""
    spans = _directive_spans(session, key)
    spans.extend((m.start(), m.end()) for m in SPDX_RE.finditer(source))
    return _strip_spans(source, spans).strip("\n")


def _preamble(session: Velvet, keys: list[str], units: dict[str, SourceUnitInfo]) -> str:
    """Merged SPDX + pragma preamble for the given source units (in order)."""
    lines: list[str] = ["// Flattened with velvet"]
    license_id = ""
    for key in keys:
        license_id = license_id or _first_spdx(units[key].source)
    if license_id:
        lines.append(f"// SPDX-License-Identifier: {license_id}")

    solidity_exprs: list[str] = []
    other_pragmas: dict[str, str] = {}  # pragma family -> full statement (first wins)
    dropped: list[str] = []
    for key in keys:
        for name, text in _pragma_statements(session, key, units[key].source):
            if name.lower() == "solidity":
                if text and text not in solidity_exprs:
                    solidity_exprs.append(text)
                continue
            full = f"pragma {text};"
            family = name.lower()
            if family not in other_pragmas:
                other_pragmas[family] = full
            elif other_pragmas[family] != full and full not in dropped:
                dropped.append(full)
    if solidity_exprs:
        lines.append(f"pragma solidity {' '.join(solidity_exprs)};")
    lines.extend(other_pragmas.values())
    for pragma in dropped:
        lines.append(f"// NOTE: conflicting pragma dropped: {pragma}")
    return "\n".join(lines)


def _first_spdx(source: str) -> str:
    match = SPDX_RE.search(source)
    return match.group("license") if match else ""


def _pragma_statements(
    session: Velvet, key: str, source: str
) -> list[tuple[str, str]]:
    """``(name, statement-text)`` for each pragma of one file, in file order.

    The statement text is recovered from the source span so the original
    spacing of version constraints is preserved.
    """
    found: list[tuple[str, str]] = []
    for unit in session.compilation_units:
        for pragma in unit.pragmas:
            mapping = pragma.source_mapping
            if mapping.filename is None or mapping.filename.used != key:
                continue
            raw = source[mapping.start : mapping.start + mapping.length]
            text = raw.strip().rstrip(";").strip()
            if pragma.name.lower() == "solidity":
                expr = solidity_pragma_expression(raw)
                found.append((pragma.name, expr))
            else:
                found.append((pragma.name, text))
    return sorted(found, key=lambda item: item[0])  # deterministic


# ---------------------------------------------------------------------------
# flattening
# ---------------------------------------------------------------------------


def flatten_units(session: Velvet, keys: Optional[set[str]] = None) -> str:
    """Flatten the given source units (default: all) into one source text."""
    units = _source_units(session)
    graph = _import_graph(session, units)
    selected = keys if keys is not None else set(units)
    missing = selected - set(units)
    if missing:
        raise VelvetError(f"unknown source unit(s): {sorted(missing)}")
    order = [key for key in _topo_order(sorted(selected), graph) if key in selected]

    parts = [_preamble(session, order, units)]
    for key in order:
        body = _strip_source(session, key, units[key].source)
        parts.append(f"\n// ---- {key} ----\n\n{body}\n")
    return "\n".join(parts).rstrip() + "\n"


def flatten_session(session: Velvet, contract_name: Optional[str] = None) -> str:
    """Flatten the whole session, or only what ``contract_name`` needs."""
    if contract_name is None:
        return flatten_units(session)
    contract = find_contract(session, contract_name)
    units = _source_units(session)
    graph = _import_graph(session, units)
    roots = _contract_files(contract) & set(units)
    return flatten_units(session, _dependency_closure(roots, graph))


def flatten_most_derived(session: Velvet) -> dict[str, str]:
    """One flattened source per most-derived contract (§B.3.2 MostDerived)."""
    result: dict[str, str] = {}
    for contract in session.contracts_derived:
        name = contract.name
        suffix = 1
        while name in result:
            suffix += 1
            name = f"{contract.name}_{suffix}"
        result[name] = flatten_session(session, contract.name)
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="velvet-flat",
        description="Flatten a multi-file Solidity codebase into standalone source.",
    )
    parser.add_argument("target", help=".sol file, project directory or standard-JSON")
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="output file (default: stdout; onefile strategy only)",
    )
    parser.add_argument(
        "--strategy",
        choices=("onefile", "most-derived"),
        default="onefile",
        help="flattening strategy (default: onefile)",
    )
    parser.add_argument(
        "--contract",
        metavar="NAME",
        help="flatten only the source units this contract needs",
    )
    parser.add_argument(
        "--dir",
        metavar="DIR",
        default="velvet-flat",
        help="output directory for the most-derived strategy (default: velvet-flat)",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.strategy == "most-derived" and args.output:
        build_parser().error("--output is only valid with the onefile strategy")
    if args.strategy == "most-derived" and args.contract:
        build_parser().error("--contract is only valid with the onefile strategy")

    try:
        session = build_session(args.target)
        if args.strategy == "most-derived":
            flattened = flatten_most_derived(session)
            out_dir = Path(args.dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            for name, source in flattened.items():
                path = out_dir / f"{name}.sol"
                path.write_text(source, encoding="utf-8")
                print(f"velvet-flat: wrote {path}", file=sys.stderr)
            return 0

        source = flatten_session(session, args.contract)
    except VelvetError as exc:
        print(f"velvet-flat: {exc}", file=sys.stderr)
        return 2

    if args.output:
        Path(args.output).write_text(source, encoding="utf-8")
        print(f"velvet-flat: wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(source)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
