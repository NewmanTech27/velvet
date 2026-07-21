"""Solidity type reconstruction from solc AST fragments.

Two entry points, used depending on what the AST provides:

- :func:`type_from_type_name` walks a ``*TypeName`` AST node (available on
  every ``VariableDeclaration`` and on ``NewExpression`` /
  ``ElementaryTypeNameExpression``).
- :func:`type_from_type_string` parses the ``typeDescriptions.typeString``
  rendering (the only type information present on expression nodes).

User-defined references (structs, enums, contracts, user-defined value
types) are resolved eagerly through the parser context's AST-id map when
possible; otherwise a :class:`~velvet.core.variables.UnresolvedSymbol`
placeholder is left inside the :class:`UserDefinedType` and patched by the
resolution pass (see ``decl_parser.resolve_types``).

Original clean-room implementation.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any, Optional

from velvet.core.types import (
    ArrayType,
    ElementaryType,
    FunctionType,
    MappingType,
    TupleType,
    Type,
    UserDefinedType,
)
from velvet.core.variables import UnresolvedSymbol

if TYPE_CHECKING:
    from velvet.parsing.decl_parser import ParserContext

logger = logging.getLogger("velvet.parsing.types")

# Storage-location annotations that solc appends to type strings.
_LOCATION_SUFFIXES = (
    " storage ref",
    " storage pointer",
    " storage",
    " memory",
    " calldata",
    " slice",
)

# typeString prefixes that do not denote first-class types we model
# (literal-only types, builtin namespaces, `type(X)` meta types).
_OPAQUE_PREFIXES = (
    "int_const",
    "rational_const",
    "literal_string",
    "string_literal",
    "bytes_literal",
    "hex_string",
    "unicode_string",
    "msg",
    "tx",
    "block",
    "abi",
    "super",
    "type(",
    "modifier (",
)


def type_from_declaration(node: dict[str, Any], ctx: ParserContext) -> Optional[Type]:
    """Type of a VariableDeclaration-like node (typeName AST, string fallback)."""
    type_name = node.get("typeName")
    if type_name is not None:
        result = type_from_type_name(type_name, ctx)
        if result is not None:
            return result
    descriptions = node.get("typeDescriptions") or {}
    type_string = descriptions.get("typeString")
    if type_string:
        return type_from_type_string(type_string, ctx)
    return None


def type_from_type_name(node: dict[str, Any], ctx: ParserContext) -> Optional[Type]:
    """Build a Type from a ``*TypeName`` AST node."""
    node_type = node.get("nodeType")

    if node_type == "ElementaryTypeName":
        name = node.get("name", "")
        if node.get("stateMutability") == "payable":
            name = f"{name} payable"
        return ElementaryType(name)

    if node_type == "ArrayTypeName":
        elem = type_from_type_name(node.get("baseType", {}), ctx)
        if elem is None:
            return None
        length: Optional[int] = None
        length_node = node.get("length")
        if length_node is not None:
            try:
                length = int(length_node.get("value", ""))
            except (TypeError, ValueError):
                # Constant-expression length (e.g. `[N]` with N a constant):
                # model as dynamic; documented limitation.
                length = None
        return ArrayType(elem, length)

    if node_type == "Mapping":
        key = type_from_type_name(node.get("keyType", {}), ctx)
        value = type_from_type_name(node.get("valueType", {}), ctx)
        if key is None or value is None:
            return None
        return MappingType(key, value)

    if node_type == "UserDefinedTypeName":
        ref_id: Optional[int] = None
        name = ""
        path_node = node.get("pathNode")
        if isinstance(path_node, dict):  # solc >= 0.8
            ref_id = path_node.get("referencedDeclaration")
            name = path_node.get("name", "")
        if not name:
            name = node.get("namePath") or node.get("name", "")
        target = ctx.id_map.get(ref_id) if isinstance(ref_id, int) else None
        if target is None:
            target = UnresolvedSymbol(name, ref_id)
        return UserDefinedType(target)

    if node_type == "FunctionTypeName":
        params = _types_from_parameter_list(node.get("parameterTypes"), ctx)
        returns = _types_from_parameter_list(node.get("returnParameterTypes"), ctx)
        return FunctionType(params, returns)

    # Older compact ASTs occasionally spell an elementary expression's type
    # as a bare string; be forgiving.
    if isinstance(node.get("name"), str):
        return ElementaryType(node["name"])
    return None


def _types_from_parameter_list(
    node: Optional[dict[str, Any]], ctx: ParserContext
) -> list[Type]:
    if not node:
        return []
    result: list[Type] = []
    for param in node.get("parameters", []) or []:
        t = type_from_declaration(param, ctx)
        if t is not None:
            result.append(t)
    return result


# --------------------------------------------------------------------- strings

_ARRAY_SUFFIX_RE = re.compile(r"\[(\d*)\]$")


def type_from_type_string(type_string: str, ctx: ParserContext) -> Optional[Type]:
    """Parse a solc ``typeDescriptions.typeString`` into a Type.

    Returns None for strings that do not denote modelable types (literal
    kinds such as ``int_const 5``, builtin namespaces like ``msg``).
    """
    text = type_string.strip()
    for suffix in _LOCATION_SUFFIXES:
        if text.endswith(suffix):
            text = text[: -len(suffix)].strip()
            break
    if not text or text.startswith(_OPAQUE_PREFIXES):
        return None
    try:
        return _parse_type(text, ctx)
    except Exception:  # noqa: BLE001 - parsing must degrade, not crash
        logger.debug("Could not parse type string %r", type_string)
        return None


def _parse_type(text: str, ctx: ParserContext) -> Type:
    # Strip array suffixes from the end (innermost first), then re-wrap.
    suffixes: list[Optional[int]] = []
    base = text
    while True:
        match = _ARRAY_SUFFIX_RE.search(base)
        if not match:
            break
        suffixes.append(int(match.group(1)) if match.group(1) else None)
        base = base[: match.start()].strip()

    result = _parse_base(base, ctx)
    # Suffixes were stripped outermost-first; re-wrap innermost-first so
    # `uint256[3][]` becomes a dynamic array of uint256[3].
    for length in reversed(suffixes):
        result = ArrayType(result, length)
    return result


def _parse_base(base: str, ctx: ParserContext) -> Type:
    if base.startswith("mapping(") and base.endswith(")"):
        inner = base[len("mapping(") : -1]
        key_str, value_str = _split_mapping(inner)
        return MappingType(_parse_type(key_str, ctx), _parse_type(value_str, ctx))

    for prefix in ("contract ", "struct ", "enum "):
        if base.startswith(prefix):
            name = base[len(prefix) :].strip()
            target = ctx.resolve_type_name(name)
            if target is None:
                target = UnresolvedSymbol(name)
            return UserDefinedType(target)

    if base.startswith("function"):
        return _parse_function_type(base, ctx)

    if base.startswith("tuple(") and base.endswith(")"):
        inner = base[len("tuple(") : -1]
        elems = (
            [_parse_type(part, ctx) for part in _split_top_level(inner)]
            if inner.strip()
            else []
        )
        return TupleType(elems)

    return ElementaryType(base)


def _split_mapping(inner: str) -> tuple[str, str]:
    """Split `key => value` at the top-level arrow."""
    depth = 0
    for idx, ch in enumerate(inner):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "=" and depth == 0 and inner[idx : idx + 2] == "=>":
            return inner[:idx].strip(), inner[idx + 2 :].strip()
    raise ValueError(f"malformed mapping type string: mapping({inner})")


def _split_top_level(text: str, delimiter: str = ",") -> list[str]:
    """Split on `delimiter` occurrences that are not nested in parens/brackets."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == delimiter and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _parse_function_type(text: str, ctx: ParserContext) -> FunctionType:
    """Parse e.g. `function (uint256) external view returns (bool)`."""
    rest = text[len("function") :].lstrip()
    params: list[Type] = []
    returns: list[Type] = []
    if rest.startswith("("):
        inner, rest = _extract_parenthesized(rest)
        if inner.strip():
            params = [_parse_type(part, ctx) for part in _split_top_level(inner)]
    marker = "returns"
    idx = rest.find(marker)
    if idx >= 0:
        tail = rest[idx + len(marker) :].lstrip()
        if tail.startswith("("):
            inner, _ = _extract_parenthesized(tail)
            if inner.strip():
                returns = [_parse_type(part, ctx) for part in _split_top_level(inner)]
    return FunctionType(params, returns)


def _extract_parenthesized(text: str) -> tuple[str, str]:
    """Split `(…)<rest>` into (inner, rest) honoring nesting."""
    depth = 0
    for idx, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[1:idx], text[idx + 1 :]
    raise ValueError(f"unbalanced parentheses in type string: {text!r}")


def resolve_unresolved_type(type_: Optional[Type], ctx: ParserContext) -> None:
    """Patch UnresolvedSymbol placeholders inside a type tree, in place."""
    if type_ is None:
        return
    if isinstance(type_, UserDefinedType):
        target = type_.type
        if isinstance(target, UnresolvedSymbol):
            resolved: Any = None
            if target.ref_id is not None:
                resolved = ctx.id_map.get(target.ref_id)
            if resolved is None and target.name:
                resolved = ctx.resolve_type_name(target.name)
            if resolved is not None:
                type_.type = resolved
    elif isinstance(type_, ArrayType):
        resolve_unresolved_type(type_.type, ctx)
    elif isinstance(type_, MappingType):
        resolve_unresolved_type(type_.type_from, ctx)
        resolve_unresolved_type(type_.type_to, ctx)
    elif isinstance(type_, FunctionType):
        for sub in type_.params + type_.returns:
            resolve_unresolved_type(sub, ctx)
    elif isinstance(type_, TupleType):
        for sub in type_.types:
            resolve_unresolved_type(sub, ctx)
