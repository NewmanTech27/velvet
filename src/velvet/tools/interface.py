"""``velvet-interface`` — Solidity interface generator (§B.4).

Generates a standalone, compilable ``interface I<Contract>`` exposing a
contract's external surface:

- every ``public``/``external`` function (incl. inherited, honoring
  overrides) as an ``external`` function prototype with original parameter
  types/names, mutability and return types;
- implicit getters of ``public`` state variables (part of the external
  surface);
- supporting declarations, individually excludable: events
  (``--exclude-events``), custom errors (``--exclude-errors``), enums
  (``--exclude-enums``) and structs (``--exclude-structs``);
- ``--unroll-structs`` expands struct-typed parameters/returns into their
  underlying component types so no struct definitions are needed (a struct
  that cannot be expanded, e.g. one containing a mapping, is kept and its
  definition is force-included).

Constructors are never emitted (interfaces cannot declare them); fallback and
receive are omitted with an explanatory comment (not representable as
prototypes). Contract-typed parameters are rendered as ``address`` so the
generated file is self-contained.

Invocation: ``velvet-interface TARGET CONTRACT`` (Solidity source on stdout).
Exit code: 0 = success, 2 = usage/compilation error.

Original clean-room implementation.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from typing import Optional, Union

from velvet.core.contract import Contract
from velvet.core.declarations import Enum, Event, Structure
from velvet.core.function import Function, FunctionKind
from velvet.core.types import ArrayType, MappingType, Type, UserDefinedType
from velvet.exceptions import VelvetError
from velvet.session import Velvet
from velvet.tools.common import (
    GetterFunction,
    available_enums,
    available_errors,
    available_events,
    available_structures,
    build_session,
    find_contract,
    is_reference_type,
    merged_solidity_pragma,
    mutability_of,
    public_getters,
    spdx_license,
    type_to_solidity,
)


# ---------------------------------------------------------------------------
# rendering context
# ---------------------------------------------------------------------------


@dataclass
class _RenderContext:
    """Collects supporting declarations required by rendered signatures."""

    unroll_structs: bool = False
    include_structs: bool = True
    include_enums: bool = True
    extra_structs: list[Structure] = field(default_factory=list)
    extra_enums: list[Enum] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)

    def require_type(self, type_: Optional[Type]) -> None:
        """Force-include the declaration of a user-defined type (closure)."""
        if isinstance(type_, ArrayType):
            self.require_type(type_.type)
            return
        if not isinstance(type_, UserDefinedType):
            return
        target = type_.type
        if isinstance(target, Structure) and self.include_structs:
            if all(s is not target for s in self.extra_structs):
                self.extra_structs.append(target)
                for elem in target.elems:
                    self.require_type(elem.type)
        elif isinstance(target, Enum) and self.include_enums:
            if all(e is not target for e in self.extra_enums):
                self.extra_enums.append(target)

    def unroll(self, type_: Type) -> Optional[list[Type]]:
        """Expand a struct type into component types; None = cannot expand."""
        if not self.unroll_structs:
            return [type_]
        if isinstance(type_, ArrayType):
            inner = self.unroll(type_.type)
            if inner is None or len(inner) != 1:
                return None  # arrays of structs keep the struct type
            return [type_]
        if not isinstance(type_, UserDefinedType) or not isinstance(
            getattr(type_, "type", None), Structure
        ):
            return [type_]
        struct: Structure = type_.type
        components: list[Type] = []
        for elem in struct.elems:
            if isinstance(elem.type, MappingType):
                return None  # mappings have no ABI representation
            expanded = self.unroll(elem.type)
            if expanded is None:
                return None
            components.extend(expanded)
        self.comments.append(
            f"// struct {struct.name} unrolled to ({', '.join(type_to_solidity(c) for c in components)})"
        )
        return components


def _self_contained_type_text(type_: Optional[Type]) -> str:
    """Type text that compiles without external contract declarations.

    Contract-typed values (including inside arrays and mappings) are rendered
    as ``address`` so the generated interface is self-contained.
    """
    if isinstance(type_, ArrayType):
        suffix = "[]" if type_.length is None else f"[{type_.length}]"
        return f"{_self_contained_type_text(type_.type)}{suffix}"
    if isinstance(type_, MappingType):
        return (
            f"mapping({_self_contained_type_text(type_.type_from)}"
            f" => {_self_contained_type_text(type_.type_to)})"
        )
    if isinstance(type_, UserDefinedType) and isinstance(
        getattr(type_, "type", None), Contract
    ):
        return "address"
    return type_to_solidity(type_)


def _render_param(
    type_: Optional[Type], name: str, location: str, ctx: _RenderContext
) -> str:
    if isinstance(type_, UserDefinedType) and isinstance(
        getattr(type_, "type", None), Contract
    ):
        text = "address"
    else:
        text = _self_contained_type_text(type_)
        ctx.require_type(type_)
    parts = [text]
    if location and is_reference_type(type_):
        parts.append(location)
    if name:
        parts.append(name)
    return " ".join(parts)


def _render_decl(
    type_: Optional[Type], name: str, location: str, ctx: _RenderContext
) -> list[str]:
    """Render one parameter/return declaration (several when unrolled)."""
    if type_ is None:
        return []
    expanded = ctx.unroll(type_)
    if expanded is None:
        ctx.require_type(type_)
        return [_render_param(type_, name, location, ctx)]
    if len(expanded) == 1 and expanded[0] is type_:
        return [_render_param(type_, name, location, ctx)]
    return [_render_param(t, "", location, ctx) for t in expanded]


def _render_function(
    function: Union[Function, GetterFunction], ctx: _RenderContext
) -> str:
    params: list[str] = []
    returns: list[str] = []
    if isinstance(function, Function):
        for param in function.parameters:
            params.extend(_render_decl(param.type, param.name, "calldata", ctx))
        for ret in function.returns:
            returns.extend(_render_decl(ret.type, ret.name, "memory", ctx))
    else:  # implicit getter
        for type_ in function.param_types:
            params.extend(_render_decl(type_, "", "calldata", ctx))
        for type_ in function.return_types:
            returns.extend(_render_decl(type_, "", "memory", ctx))

    mutability = mutability_of(function)
    suffix = "" if mutability == "nonpayable" else f" {mutability}"
    return_clause = f" returns ({', '.join(returns)})" if returns else ""
    return (
        f"function {function.name}({', '.join(params)})"
        f" external{suffix}{return_clause};"
    )


def _render_event(event: Event) -> str:
    params = []
    for elem in event.elems:
        parts = [type_to_solidity(elem.type)]
        if elem.indexed:
            parts.append("indexed")
        if elem.name:
            parts.append(elem.name)
        params.append(" ".join(parts))
    return f"event {event.name}({', '.join(params)});"


def _render_error(error) -> str:
    params = []
    for name, type_ in error.parameters:
        parts = [type_to_solidity(type_)]
        if name:
            parts.append(name)
        params.append(" ".join(parts))
    return f"error {error.name}({', '.join(params)});"


def _render_enum(enum: Enum) -> str:
    return f"enum {enum.name} {{ {', '.join(enum.values)} }}"


def _render_struct(struct: Structure) -> str:
    lines = [f"struct {struct.name} {{"]
    for elem in struct.elems:
        lines.append(f"    {_self_contained_type_text(elem.type)} {elem.name};")
    lines.append("}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# interface generation
# ---------------------------------------------------------------------------


def generate_interface(
    contract: Contract,
    session: Optional[Velvet] = None,
    *,
    name: Optional[str] = None,
    include_events: bool = True,
    include_errors: bool = True,
    include_enums: bool = True,
    include_structs: bool = True,
    unroll_structs: bool = False,
) -> str:
    """Generate ``interface I<Contract>`` source for ``contract``."""
    interface_name = name or f"I{contract.name}"
    ctx = _RenderContext(
        unroll_structs=unroll_structs,
        include_structs=include_structs,
        include_enums=include_enums,
    )

    # ---- function surface (prototypes rendered first so type requirements
    # are collected before the supporting declarations are emitted)
    function_lines: list[str] = []
    seen_signatures: set[str] = set()
    for function in contract.functions_entry_points:
        if function.kind != FunctionKind.NORMAL:
            continue  # constructor / fallback / receive
        if function.signature in seen_signatures:
            continue
        seen_signatures.add(function.signature)
        function_lines.append(_render_function(function, ctx))
    for getter in public_getters(contract):
        if getter.signature in seen_signatures:
            continue
        seen_signatures.add(getter.signature)
        function_lines.append(_render_function(getter, ctx))
    if contract.has_fallback or contract.has_receive:
        ctx.comments.append(
            "// fallback/receive omitted: not representable as interface prototypes"
        )

    # ---- supporting declarations
    declaration_lines: list[str] = []
    if include_enums:
        enums = [*available_enums(contract), *ctx.extra_enums]
        declaration_lines.extend(_render_enum(e) for e in _unique(enums))
    if include_structs:
        structs = [*available_structures(contract), *ctx.extra_structs]
        declaration_lines.extend(_render_struct(s) for s in _unique(structs))
    if include_errors:
        declaration_lines.extend(_render_error(e) for e in available_errors(contract))
    if include_events:
        declaration_lines.extend(_render_event(e) for e in available_events(contract))

    # ---- file preamble
    preamble: list[str] = [f"// Interface for {contract.name} generated by velvet"]
    if session is not None:
        sources = [
            info.source
            for unit in session.compilation_units
            for info in unit.compilation.source_units.values()
        ]
        license_id = next((lic for s in sources if (lic := spdx_license(s))), "")
        if license_id:
            preamble.insert(0, f"// SPDX-License-Identifier: {license_id}")
        pragma_expr = merged_solidity_pragma(sources)
        if pragma_expr:
            preamble.append(f"pragma solidity {pragma_expr};")

    body: list[str] = []
    body.extend(f"    {line}" for line in ctx.comments)
    for declaration in declaration_lines:
        body.extend(f"    {line}" for line in declaration.splitlines())
    body.extend(f"    {line}" for line in function_lines)
    while body and not body[0]:
        body.pop(0)

    parts = ["\n".join(preamble), "", f"interface {interface_name} {{"]
    parts.extend(body or ["    // (no external functions)"])
    parts.append("}")
    return "\n".join(parts) + "\n"


def _unique(items: list) -> list:
    result: list = []
    seen: set[int] = set()
    for item in items:
        if id(item) not in seen:
            seen.add(id(item))
            result.append(item)
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="velvet-interface",
        description="Generate a Solidity interface for a contract.",
    )
    parser.add_argument("target", help=".sol file, project directory or standard-JSON")
    parser.add_argument("contract", help="contract to generate the interface for")
    parser.add_argument("--name", metavar="NAME", help="interface name (default: I<Contract>)")
    parser.add_argument("--exclude-events", action="store_true", help="omit event signatures")
    parser.add_argument("--exclude-errors", action="store_true", help="omit custom error signatures")
    parser.add_argument("--exclude-enums", action="store_true", help="omit enum definitions")
    parser.add_argument("--exclude-structs", action="store_true", help="omit struct definitions")
    parser.add_argument(
        "--unroll-structs",
        action="store_true",
        help="expand struct parameters/returns into their component types",
    )
    parser.add_argument("-o", "--output", metavar="FILE", help="output file (default: stdout)")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        session = build_session(args.target)
        contract = find_contract(session, args.contract)
        source = generate_interface(
            contract,
            session,
            name=args.name,
            include_events=not args.exclude_events,
            include_errors=not args.exclude_errors,
            include_enums=not args.exclude_enums,
            include_structs=not args.exclude_structs,
            unroll_structs=args.unroll_structs,
        )
    except VelvetError as exc:
        print(f"velvet-interface: {exc}", file=sys.stderr)
        return 2

    if args.output:
        from pathlib import Path

        Path(args.output).write_text(source, encoding="utf-8")
        print(f"velvet-interface: wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(source)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
