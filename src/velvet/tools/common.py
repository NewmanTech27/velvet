"""Shared helpers for the velvet companion tools (spec/printers-and-tools.md §B).

These helpers bridge the core model to the needs of the auxiliary tools:

- session/contract lookup with tool-friendly errors;
- canonical type rendering (for signature matching and code generation);
- synthesized public state-variable getters (Solidity implicitly generates a
  getter function for every ``public`` state variable; the core model keeps
  them as variables, so the tools synthesize the function view here);
- inheritance-aware event/error/enum/struct collection;
- transitive event-emission detection (through modifiers and internal calls).

Original clean-room implementation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Union

from velvet.core.contract import Contract
from velvet.core.declarations import CustomError, Enum, Event, Structure
from velvet.core.function import Function
from velvet.core.types import (
    ArrayType,
    ElementaryType,
    MappingType,
    Type,
    UserDefinedType,
)
from velvet.core.variables import StateVariable
from velvet.exceptions import VelvetError
from velvet.session import Velvet

# ---------------------------------------------------------------------------
# session / contract lookup
# ---------------------------------------------------------------------------


def build_session(target: str, **options) -> Velvet:
    """Run the full velvet pipeline on ``target`` and return the session."""
    return Velvet(target, **options)


def find_contract(session: Velvet, name: str) -> Contract:
    """Resolve ``name`` to a single contract or raise a tool-friendly error."""
    found = session.get_contract_from_name(name)
    if found is None:
        available = ", ".join(sorted({c.name for c in session.contracts}))
        raise VelvetError(
            f"contract {name!r} not found in {session.target!r} "
            f"(available: {available or 'none'})"
        )
    if isinstance(found, list):
        raise VelvetError(
            f"multiple contracts named {name!r} found; "
            "disambiguate by using a narrower target"
        )
    return found


# ---------------------------------------------------------------------------
# canonical type handling
# ---------------------------------------------------------------------------


def canonical_type(type_: Optional[Type]) -> str:
    """Canonical type string used for ERC signature matching.

    ``uint``/``int`` aliases are already normalized to ``uint256``/``int256``
    by :class:`~velvet.core.types.ElementaryType`.
    """
    return str(type_) if type_ is not None else ""


def canonical_params(function: Union[Function, "GetterFunction"]) -> list[str]:
    return [canonical_type(t) for t in _param_types(function)]


def canonical_returns(function: Union[Function, "GetterFunction"]) -> list[str]:
    return [canonical_type(t) for t in _return_types(function)]


def _param_types(function: Union[Function, "GetterFunction"]) -> list:
    if isinstance(function, GetterFunction):
        return function.param_types
    return [p.type for p in function.parameters]


def _return_types(function: Union[Function, "GetterFunction"]) -> list:
    if isinstance(function, GetterFunction):
        return function.return_types
    return [r.type for r in function.returns]


def mutability_of(function: Union[Function, "GetterFunction"]) -> str:
    """One of ``pure`` / ``view`` / ``payable`` / ``nonpayable``."""
    if isinstance(function, GetterFunction):
        return "view"  # implicit getters are always view
    if function.pure:
        return "pure"
    if function.view:
        return "view"
    if function.payable:
        return "payable"
    return "nonpayable"


def signature_of(name: str, param_types: list[str]) -> str:
    return f"{name}({','.join(param_types)})"


# ---------------------------------------------------------------------------
# public state-variable getters
# ---------------------------------------------------------------------------


@dataclass
class GetterFunction:
    """Function view of a ``public`` state variable's implicit getter."""

    variable: StateVariable
    name: str
    param_types: list[Type] = field(default_factory=list)
    return_types: list[Type] = field(default_factory=list)
    is_implemented: bool = True

    @property
    def signature(self) -> str:
        return signature_of(self.name, [canonical_type(t) for t in self.param_types])


def _getter_parts(type_: Optional[Type]) -> Optional[tuple[list[Type], Type]]:
    """Decompose a state-variable type into getter (params, return).

    Mapping keys and array indices become parameters (outermost first, per
    Solidity getter semantics); the final value type becomes the return.
    Returns ``None`` when the getter cannot be represented (e.g. a struct
    value, whose real getter returns a tuple of members).
    """
    if type_ is None:
        return None
    params: list[Type] = []
    current = type_
    while True:
        if isinstance(current, MappingType):
            params.append(current.type_from)
            current = current.type_to
        elif isinstance(current, ArrayType):
            params.append(ElementaryType("uint256"))
            current = current.type
        else:
            break
    if isinstance(current, UserDefinedType) and isinstance(
        getattr(current, "type", None), Structure
    ):
        return None  # struct getters expand to member tuples — not modeled
    return params, current


def getter_for_variable(variable: StateVariable) -> Optional[GetterFunction]:
    """Synthesize the implicit getter for a public state variable."""
    parts = _getter_parts(variable.type)
    if parts is None:
        return None
    params, ret = parts
    return GetterFunction(
        variable=variable, name=variable.name, param_types=params, return_types=[ret]
    )


def public_getters(contract: Contract) -> list[GetterFunction]:
    """Implicit getters for all public state variables (incl. inherited)."""
    result: list[GetterFunction] = []
    for variable in contract.state_variables_ordered:
        if variable.visibility != "public":
            continue
        getter = getter_for_variable(variable)
        if getter is not None:
            result.append(getter)
    return result


# ---------------------------------------------------------------------------
# member resolution (functions + getters, inheritance-aware)
# ---------------------------------------------------------------------------


def resolve_function(
    contract: Contract, name: str, param_types: tuple[str, ...] | list[str]
) -> Optional[Union[Function, GetterFunction]]:
    """Find the effective implementation of ``name(params)`` on ``contract``.

    Searches externally-visible functions (honoring overrides) first, then
    public state-variable getters. Returns ``None`` when absent.
    """
    wanted = list(param_types)
    for function in contract.available_functions_from_inheritances():
        if function.visibility not in ("external", "public"):
            continue
        if function.name == name and canonical_params(function) == wanted:
            return function
    for getter in public_getters(contract):
        if getter.name == name and [
            canonical_type(t) for t in getter.param_types
        ] == wanted:
            return getter
    return None


def available_events(contract: Contract) -> list[Event]:
    """Events visible in ``contract`` (own + inherited), deduped by signature."""
    return _deduped(contract, lambda c: c.events)


def available_errors(contract: Contract) -> list[CustomError]:
    return _deduped(contract, lambda c: c.errors)


def available_enums(contract: Contract) -> list[Enum]:
    return _deduped(contract, lambda c: c.enums)


def available_structures(contract: Contract) -> list[Structure]:
    return _deduped(contract, lambda c: c.structures)


def _deduped(contract: Contract, member) -> list:
    result: list = []
    seen: set[str] = set()
    for current in [contract] + list(contract.inheritance):
        for item in member(current):
            sig = getattr(item, "signature", None) or getattr(item, "name", str(item))
            if sig not in seen:
                seen.add(sig)
                result.append(item)
    return result


# ---------------------------------------------------------------------------
# event emission (transitive through modifiers and internal calls)
# ---------------------------------------------------------------------------


def emitted_event_names(function: Function) -> set[str]:
    """Names of events the function may emit, incl. via modifiers and
    (transitively) internal calls such as ``_transfer`` helpers."""
    names = {call.name for call in function.event_calls}
    for target in function.all_internal_calls_reachable:
        names.update(call.name for call in target.event_calls)
    return names


# ---------------------------------------------------------------------------
# Solidity source rendering of types
# ---------------------------------------------------------------------------


def type_to_solidity(type_: Optional[Type]) -> str:
    """Render a model type back to Solidity source form."""
    if type_ is None:
        return ""
    if isinstance(type_, ArrayType):
        suffix = "[]" if type_.length is None else f"[{type_.length}]"
        return f"{type_to_solidity(type_.type)}{suffix}"
    if isinstance(type_, MappingType):
        return (
            f"mapping({type_to_solidity(type_.type_from)}"
            f" => {type_to_solidity(type_.type_to)})"
        )
    if isinstance(type_, UserDefinedType):
        return getattr(type_.type, "name", str(type_))
    return str(type_)


def is_reference_type(type_: Optional[Type]) -> bool:
    """True for types that need a data location in function signatures."""
    if isinstance(type_, ArrayType):
        return True
    if isinstance(type_, ElementaryType):
        return type_.name.split()[0] in ("string", "bytes")
    if isinstance(type_, UserDefinedType):
        return isinstance(getattr(type_, "type", None), Structure)
    return False


# ---------------------------------------------------------------------------
# Keccak-256 (Ethereum flavor) and function selectors
# ---------------------------------------------------------------------------
#
# Pure-Python Keccak-f[1600] sponge (the original Keccak padding domain
# 0x01, not SHA-3's 0x06) so selector computation needs no third-party
# crypto dependency. Implemented from the public Keccak reference.

_KECCAK_MASK64 = (1 << 64) - 1

_KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

_KECCAK_RHO_OFFSETS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_KECCAK_256_RATE = 136  # (1600 - 2 * 256) bits, in bytes


def _rotl64(value: int, shift: int) -> int:
    if shift == 0:
        return value & _KECCAK_MASK64
    return ((value << shift) | (value >> (64 - shift))) & _KECCAK_MASK64


def _keccak_f1600(state: list[int]) -> None:
    """One Keccak-f[1600] permutation over 25 little-endian 64-bit lanes."""
    for round_constant in _KECCAK_ROUND_CONSTANTS:
        # theta
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        delta = [
            columns[(x - 1) % 5] ^ _rotl64(columns[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= delta[x]
        # rho and pi
        moved = [0] * 25
        for x in range(5):
            for y in range(5):
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(
                    state[x + 5 * y], _KECCAK_RHO_OFFSETS[x][y]
                )
        # chi
        for y in range(5):
            row = moved[5 * y : 5 * y + 5]
            for x in range(5):
                state[x + 5 * y] = (
                    row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
                ) & _KECCAK_MASK64
        # iota
        state[0] ^= round_constant


def keccak256(data: bytes) -> bytes:
    """Ethereum Keccak-256 digest of ``data`` (32 bytes)."""
    state = [0] * 25
    padded = bytearray(data)
    padded.append(0x01)  # Keccak pad10*1 domain byte
    while len(padded) % _KECCAK_256_RATE:
        padded.append(0x00)
    padded[-1] |= 0x80
    for offset in range(0, len(padded), _KECCAK_256_RATE):
        block = padded[offset : offset + _KECCAK_256_RATE]
        for lane in range(_KECCAK_256_RATE // 8):
            state[lane] ^= int.from_bytes(block[8 * lane : 8 * lane + 8], "little")
        _keccak_f1600(state)
    digest = bytearray()
    while len(digest) < 32:
        for lane in range(_KECCAK_256_RATE // 8):
            digest.extend(state[lane].to_bytes(8, "little"))
        if len(digest) < 32:
            _keccak_f1600(state)
    return bytes(digest[:32])


def function_selector(signature: str) -> bytes:
    """The 4-byte function selector of a canonical signature."""
    return keccak256(signature.encode("utf-8"))[:4]


# ---------------------------------------------------------------------------
# pragma / SPDX extraction from raw sources
# ---------------------------------------------------------------------------

_SOLIDITY_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
SPDX_RE = re.compile(r"^[ \t]*//[ \t]*SPDX-License-Identifier:[ \t]*(?P<license>.*?)[ \t]*$", re.MULTILINE)


def solidity_pragma_expression(source: str) -> str:
    """Raw solidity pragma version expression of one source (``""`` if none)."""
    match = _SOLIDITY_PRAGMA_RE.search(source)
    return match.group(1).strip() if match else ""


def merged_solidity_pragma(sources: list[str]) -> str:
    """Merge the solidity pragmas of several sources into one expression.

    Whitespace-separated constraints in a version pragma are AND-ed by solc,
    so joining the distinct per-file expressions yields the intersection.
    """
    expressions: list[str] = []
    for source in sources:
        expr = solidity_pragma_expression(source)
        if expr and expr not in expressions:
            expressions.append(expr)
    return " ".join(expressions)


def spdx_license(source: str) -> str:
    """The SPDX license identifier of one source (``""`` if none)."""
    match = SPDX_RE.search(source)
    return match.group("license") if match else ""
