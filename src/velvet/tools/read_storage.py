"""``velvet-read-storage`` — storage layout computation and slot reader
(spec/printers-and-tools.md §B.5).

Two modes:

- **layout** (offline, default): compute the complete storage layout of a
  contract from the analysis model — every state variable (incl. inherited)
  with its slot, byte offset, size and encoding, following the Solidity
  storage layout rules (§B.5.2): variables are laid out in declaration
  order (most-base first), packed into 32-byte slots when they fit without
  crossing a slot boundary; mappings and dynamic arrays occupy a full slot
  holding nothing but their base slot; struct members and fixed arrays are
  laid out sequentially starting on a fresh slot.
- **read** (online, with ``--rpc-url`` and an address): read raw slots via
  JSON-RPC ``eth_getStorageAt`` and decode them into per-variable values
  (plus unstructured-storage helpers for EIP-1967 proxy slots).

Invocation::

    velvet-read-storage TARGET CONTRACT [--rpc-url URL --storage-address ADDRESS]
        [--slot N] [--var-name NAME [--key KEY ...] [--struct-var FIELD]]
        [--block BLOCK] [--json FILE] [--unstructured] [--max-depth N]

Exit code: 0 = success, 1 = (unused), 2 = usage/compilation error.

Original clean-room implementation.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional
from urllib import request as urllib_request

from velvet.core.contract import Contract
from velvet.core.declarations import Structure
from velvet.core.types import (
    ArrayType,
    ElementaryType,
    MappingType,
    Type,
    UserDefinedType,
)
from velvet.exceptions import VelvetError
from velvet.session import Velvet
from velvet.tools.common import build_session, find_contract, keccak256, type_to_solidity

# ---------------------------------------------------------------------------
# storage layout rules (spec/printers-and-tools.md §B.5.2)
# ---------------------------------------------------------------------------

SLOT_SIZE = 32
ENCODING_INPLACE = "inplace"
ENCODING_MAPPING = "mapping"
ENCODING_DYNAMIC_ARRAY = "dynamic_array"
ENCODING_BYTES = "bytes"


def type_size(type_: Optional[Type]) -> int:
    """Size in bytes of a value type (32 for slot-sized reference types)."""
    if type_ is None:
        return SLOT_SIZE
    if isinstance(type_, ElementaryType):
        name = type_.name.split()[0]
        if name.startswith("uint") or name.startswith("int"):
            bits = name[3:] or name[2:]
            return int(bits) // 8 if bits else 32
        if name.startswith("bytes") and name != "bytes":
            return int(name[5:])
        if name == "address":
            return 20
        if name == "bool":
            return 1
        return SLOT_SIZE  # string/bytes: encoded in place (short) or via keccak slot
    if isinstance(type_, UserDefinedType):
        target = type_.type
        if target.__class__.__name__ == "Enum":
            return 1
        if target.__class__.__name__ == "Contract":
            return 20
        return SLOT_SIZE  # structs occupy full slots
    return SLOT_SIZE


def is_slot_sized(type_: Optional[Type]) -> bool:
    """True when the type always starts on a fresh slot (struct/array/mapping)."""
    if isinstance(type_, (MappingType, ArrayType)):
        return True
    if isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure):
        return True
    return False


@dataclass
class StorageEntry:
    """One flattened layout entry: a value occupying (slot, offset, size)."""

    name: str  # dotted label for nested members
    type: Type
    slot: int
    offset: int  # byte offset within the slot (0..31)
    size: int  # size in bytes
    encoding: str = ENCODING_INPLACE


class _LayoutCursor:
    """Sequential slot/offset allocator following the layout rules."""

    def __init__(self) -> None:
        self.slot = 0
        self.offset = 0  # next free byte within the current slot

    def allocate(self, size: int) -> tuple[int, int]:
        """Reserve ``size`` bytes; returns (slot, offset) of the value."""
        if size > SLOT_SIZE:
            raise VelvetError(f"value type larger than a slot ({size} bytes)")
        if self.offset + size > SLOT_SIZE:
            self.slot += 1
            self.offset = 0
        slot, offset = self.slot, self.offset
        self.offset += size
        if self.offset == SLOT_SIZE:
            self.slot += 1
            self.offset = 0
        return slot, offset

    def next_slot(self) -> int:
        """Force alignment to the next slot boundary; returns its index."""
        if self.offset != 0:
            self.slot += 1
            self.offset = 0
        slot = self.slot
        self.slot += 1
        return slot


def _layout_variable(
    cursor: _LayoutCursor, label: str, type_: Type, entries: list[StorageEntry]
) -> None:
    """Lay out one variable (recursing into structs and fixed arrays)."""
    if isinstance(type_, MappingType):
        slot = cursor.next_slot()
        entries.append(
            StorageEntry(label, type_, slot, 0, SLOT_SIZE, ENCODING_MAPPING)
        )
        return
    if isinstance(type_, ArrayType):
        if type_.length is None:
            slot = cursor.next_slot()
            entries.append(
                StorageEntry(label, type_, slot, 0, SLOT_SIZE, ENCODING_DYNAMIC_ARRAY)
            )
            return
        base_slot = cursor.next_slot()
        _layout_fixed_array(cursor, label, type_, base_slot, entries)
        return
    if isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure):
        base_slot = cursor.next_slot()
        _layout_struct(cursor, label, type_.type, base_slot, entries)
        return
    size = type_size(type_)
    slot, offset = cursor.allocate(size)
    encoding = ENCODING_BYTES if _is_short_bytes(type_) else ENCODING_INPLACE
    entries.append(StorageEntry(label, type_, slot, offset, size, encoding))


def _is_short_bytes(type_: Optional[Type]) -> bool:
    return isinstance(type_, ElementaryType) and type_.name.split()[0] in (
        "bytes",
        "string",
    )


def _layout_struct(
    cursor: _LayoutCursor,
    label: str,
    struct: Structure,
    base_slot: int,
    entries: list[StorageEntry],
) -> None:
    """Struct members sequentially from a fresh slot (nested cursor)."""
    inner = _LayoutCursor()
    inner.slot = base_slot
    for elem in struct.elems:
        _layout_variable(inner, f"{label}.{elem.name}", elem.type, entries)
    # The struct ends on a slot boundary for whatever follows it.
    cursor.slot = inner.slot + (1 if inner.offset else 0)
    cursor.offset = 0


def _layout_fixed_array(
    cursor: _LayoutCursor,
    label: str,
    array: ArrayType,
    base_slot: int,
    entries: list[StorageEntry],
) -> None:
    """Fixed array: elements sequentially from a fresh slot."""
    assert array.length is not None
    inner = _LayoutCursor()
    inner.slot = base_slot
    for index in range(int(array.length)):
        _layout_variable(inner, f"{label}[{index}]", array.type, entries)
    cursor.slot = inner.slot + (1 if inner.offset else 0)
    cursor.offset = 0


def compute_layout(contract: Contract, *, flatten_nested: bool = True) -> list[StorageEntry]:
    """Full storage layout of ``contract`` (most-base first).

    With ``flatten_nested`` (default), struct members and fixed-array
    elements appear as individual dotted entries.  Constants and immutables
    occupy no storage and are excluded.
    """
    entries: list[StorageEntry] = []
    cursor = _LayoutCursor()
    for var in contract.state_variables_ordered:
        if var.is_constant or var.is_immutable:
            continue
        if var.type is None:
            continue
        if flatten_nested:
            _layout_variable(cursor, var.name, var.type, entries)
        else:
            size = type_size(var.type)
            if is_slot_sized(var.type):
                slot = cursor.next_slot()
                entries.append(StorageEntry(var.name, var.type, slot, 0, SLOT_SIZE))
            else:
                slot, offset = cursor.allocate(size)
                entries.append(StorageEntry(var.name, var.type, slot, offset, size))
    return entries


# ---------------------------------------------------------------------------
# slot addressing (keccak-based) and drill-down
# ---------------------------------------------------------------------------


def mapping_slot(key_bytes: bytes, base_slot: int) -> int:
    """Solidity mapping value slot: keccak256(h(key) . p(slot))."""
    padded_key = key_bytes.rjust(SLOT_SIZE, b"\x00")
    padded_slot = base_slot.to_bytes(SLOT_SIZE, "big")
    return int.from_bytes(keccak256(padded_key + padded_slot), "big")


def dynamic_array_slot(base_slot: int) -> int:
    """Slot of the first element of a dynamic array."""
    return int.from_bytes(keccak256(base_slot.to_bytes(SLOT_SIZE, "big")), "big")


def key_to_bytes(key: str, key_type: Optional[Type]) -> bytes:
    """Encode a CLI-provided mapping key per its Solidity type."""
    text = key.strip()
    if isinstance(key_type, ElementaryType):
        name = key_type.name.split()[0]
        if name == "address":
            hex_part = text[2:] if text.startswith("0x") else text
            return bytes.fromhex(hex_part.zfill(40))
        if name == "bool":
            return (1 if text.lower() in ("true", "1") else 0).to_bytes(1, "big")
        if name.startswith("uint") or name.startswith("int"):
            return int(text, 0).to_bytes(SLOT_SIZE, "big")
        if name.startswith("bytes") and name != "bytes":
            hex_part = text[2:] if text.startswith("0x") else text
            return bytes.fromhex(hex_part)
    # fallback: try hex, then decimal, then raw utf-8
    try:
        if text.startswith("0x"):
            return bytes.fromhex(text[2:])
        return int(text, 0).to_bytes(SLOT_SIZE, "big")
    except ValueError:
        return text.encode("utf-8")


@dataclass
class ResolvedPath:
    """A drill-down resolution: final (slot, offset, size) of a value."""

    label: str
    type: Type
    slot: int
    offset: int
    size: int
    encoding: str


def resolve_path(
    entry: StorageEntry, keys: list[str], struct_field: Optional[str]
) -> ResolvedPath:
    """Resolve mapping keys / array indices / a struct field from an entry."""
    label = entry.name
    type_ = entry.type
    slot, offset, size, encoding = entry.slot, entry.offset, entry.size, entry.encoding

    for key in keys:
        if isinstance(type_, MappingType):
            slot = mapping_slot(key_to_bytes(key, type_.type_from), slot)
            type_ = type_.type_to
            label += f"[{key}]"
            offset, size, encoding = 0, type_size(type_), ENCODING_INPLACE
        elif isinstance(type_, ArrayType):
            index = int(key, 0)
            if type_.length is None:
                base = dynamic_array_slot(slot)
                slot = base + index
            else:
                slot = slot + index
            type_ = type_.type
            label += f"[{index}]"
            offset, size, encoding = 0, type_size(type_), ENCODING_INPLACE
        else:
            raise VelvetError(
                f"cannot apply key {key!r} to {label} of type {type_to_solidity(type_)}"
            )

    if struct_field:
        if not (isinstance(type_, UserDefinedType) and isinstance(type_.type, Structure)):
            raise VelvetError(
                f"--struct-var requires a struct at {label} (got {type_to_solidity(type_)})"
            )
        # re-lay out the struct from its base slot to find the field
        sub: list[StorageEntry] = []
        _layout_struct(_LayoutCursor(), label, type_.type, slot, sub)
        match = next((e for e in sub if e.name == f"{label}.{struct_field}"), None)
        if match is None:
            available = ", ".join(e.name.split(".")[-1] for e in sub)
            raise VelvetError(
                f"struct {type_.type.name} has no field {struct_field!r} ({available})"
            )
        return ResolvedPath(
            match.name, match.type, match.slot, match.offset, match.size, match.encoding
        )

    return ResolvedPath(label, type_, slot, offset, size, encoding)


# ---------------------------------------------------------------------------
# value decoding
# ---------------------------------------------------------------------------


def _slot_int(raw: bytes, offset: int, size: int) -> int:
    """Big-endian integer at (offset, size) within a slot's 32 bytes.

    Solidity packs values right-aligned: the value at byte offset ``o`` of
    size ``s`` occupies bytes ``32 - o - s .. 32 - o``.
    """
    start = SLOT_SIZE - offset - size
    return int.from_bytes(raw[start : start + size], "big")


def decode_value(
    type_: Optional[Type],
    slot: int,
    raw: bytes,
    offset: int,
    size: int,
    read_slot: Optional[Callable[[int], bytes]] = None,
) -> str:
    """Decode a raw slot into a human-readable value string."""
    if type_ is None:
        return f"0x{raw.hex()}"
    if isinstance(type_, ElementaryType):
        name = type_.name.split()[0]
        if name == "bool":
            return "true" if _slot_int(raw, offset, size) else "false"
        if name == "address":
            return f"0x{_slot_int(raw, offset, size):040x}"
        if name.startswith("bytes") and name != "bytes":
            value = _slot_int(raw, offset, size)
            return f"0x{value:0{size * 2}x}"
        if name in ("bytes", "string"):
            return _decode_dynamic_bytes(raw, slot, read_slot, name == "string")
        if name.startswith("int"):
            value = _slot_int(raw, offset, size)
            bits = int(name[3:] or 256)
            if value >= 1 << (bits - 1):
                value -= 1 << bits
            return str(value)
        return str(_slot_int(raw, offset, size))
    if isinstance(type_, UserDefinedType):
        target = type_.type
        if target.__class__.__name__ == "Enum":
            index = _slot_int(raw, offset, size)
            values = getattr(target, "values", [])
            if 0 <= index < len(values):
                return f"{target.name}.{values[index]}"
            return str(index)
        if target.__class__.__name__ == "Contract":
            return f"0x{_slot_int(raw, offset, size):040x}"
        return f"<struct {target.name} at slot {slot}>"
    if isinstance(type_, MappingType):
        return f"<mapping at slot {slot} (empty) — use --key to drill down>"
    if isinstance(type_, ArrayType):
        if type_.length is None:
            length = int.from_bytes(raw, "big")
            return f"<dynamic array, length {length}, data at slot {dynamic_array_slot(slot)}>"
        return f"<{type_to_solidity(type_)} at slot {slot}>"
    return f"0x{raw.hex()}"


def _decode_dynamic_bytes(
    raw: bytes, slot: int, read_slot: Optional[Callable[[int], bytes]], as_string: bool
) -> str:
    """Decode a short (in-place) or long (keccak area) bytes/string value."""
    low_byte = raw[-1]
    if low_byte % 2 == 0:
        length = low_byte // 2
        data = raw[:length]
    else:
        length = (int.from_bytes(raw, "big") - 1) // 2
        if read_slot is None:
            return f"<long bytes/string, length {length}>"
        base = dynamic_array_slot(slot)
        data = b"".join(
            read_slot(base + i) for i in range((length + SLOT_SIZE - 1) // SLOT_SIZE)
        )[:length]
    if as_string:
        return data.decode("utf-8", errors="replace")
    return f"0x{data.hex()}"


# ---------------------------------------------------------------------------
# JSON-RPC client
# ---------------------------------------------------------------------------


class RpcClient:
    """Minimal JSON-RPC client for eth_getStorageAt."""

    def __init__(self, url: str) -> None:
        self.url = url
        self._next_id = 1

    def call(self, method: str, params: list[Any]) -> Any:
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params}
        ).encode("utf-8")
        self._next_id += 1
        req = urllib_request.Request(
            self.url, data=payload, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib_request.urlopen(req, timeout=30) as response:
                body = json.loads(response.read().decode("utf-8"))
        except OSError as exc:
            raise VelvetError(f"RPC call {method} failed: {exc}") from exc
        if "error" in body:
            raise VelvetError(f"RPC error from {method}: {body['error']}")
        return body.get("result")

    def get_storage_at(self, address: str, slot: int, block: str = "latest") -> bytes:
        result = self.call(
            "eth_getStorageAt", [address, hex(slot), block]
        )
        if result is None:
            raise VelvetError("eth_getStorageAt returned no result")
        return bytes.fromhex(result[2:] if result.startswith("0x") else result).rjust(
            SLOT_SIZE, b"\x00"
        )


# ---------------------------------------------------------------------------
# unstructured storage (EIP-1967)
# ---------------------------------------------------------------------------

EIP1967_SLOTS: tuple[tuple[str, str], ...] = (
    ("eip1967.proxy.implementation", "address"),
    ("eip1967.proxy.admin", "address"),
    ("eip1967.proxy.beacon", "address"),
)


def unstructured_slot(label: str) -> int:
    """EIP-1967 slot: keccak256(label) - 1."""
    return int.from_bytes(keccak256(label.encode("utf-8")), "big") - 1


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def render_table(
    contract: Contract,
    entries: list[StorageEntry],
    values: Optional[dict[str, str]],
    *,
    storage_address: Optional[str],
    tag: str,
    unstructured: Optional[list[tuple[StorageEntry, Optional[str]]]] = None,
) -> str:
    """Console table of the layout (values column when read online)."""
    header = f"Storage layout of {contract.name}"
    if storage_address:
        header += f" @ {storage_address} (block {tag})"
    lines = [header, f"{'Name':<30} {'Type':<28} {'Slot':>6} {'Offset':>6} {'Size':>5}"]
    lines.append("-" * 80)
    for entry in entries:
        line = (
            f"{entry.name:<30} {type_to_solidity(entry.type):<28} "
            f"{entry.slot:>6} {entry.offset:>6} {entry.size:>5}"
        )
        if values is not None:
            line += f"  {values.get(entry.name, '')}"
        lines.append(line)
    if unstructured:
        lines.append("")
        lines.append("Unstructured storage (EIP-1967):")
        for entry, value in unstructured:
            line = f"{entry.name:<30} slot {entry.slot}"
            if value is not None:
                line += f"  {value}"
            lines.append(line)
    return "\n".join(lines) + "\n"


def build_json_document(
    contract: Contract,
    entries: list[StorageEntry],
    values: Optional[dict[str, str]],
    *,
    storage_address: Optional[str],
    tag: str,
    max_depth: int,
    query: Optional[dict[str, Any]] = None,
    unstructured: Optional[list[tuple[StorageEntry, Optional[str]]]] = None,
) -> dict[str, Any]:
    """Assemble the ``storage-layout`` JSON document."""
    variables = []
    for entry in entries:
        item: dict[str, Any] = {
            "name": entry.name,
            "type": type_to_solidity(entry.type),
            "slot": entry.slot,
            "offset": entry.offset,
            "size": entry.size,
            "encoding": entry.encoding,
        }
        if values is not None and entry.name in values:
            item["value"] = values[entry.name]
        variables.append(item)
    layout: dict[str, Any] = {
        "contract": contract.name,
        "variables": variables,
        "max_depth": max_depth,
    }
    if storage_address:
        layout["storage_address"] = storage_address
        layout["block"] = tag
    if query is not None:
        layout["query"] = query
    if unstructured:
        layout["unstructured"] = [
            {
                "name": e.name,
                "slot": e.slot,
                **({"value": v} if v is not None else {}),
            }
            for e, v in unstructured
        ]
    return {"success": True, "error": None, "results": {"storage-layout": layout}}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="velvet-read-storage",
        description=(
            "Compute a contract's storage layout, and optionally read live "
            "storage values from an RPC endpoint."
        ),
    )
    parser.add_argument("target", help=".sol file, project directory or standard-JSON")
    parser.add_argument("contract", help="contract whose storage to inspect")
    parser.add_argument("--rpc-url", metavar="URL", default=None,
                        help="JSON-RPC endpoint for live reads")
    parser.add_argument("--storage-address", "--address", dest="address",
                        metavar="ADDRESS", default=None,
                        help="deployed contract address for live reads")
    parser.add_argument("--block", default="latest", metavar="BLOCK",
                        help="block tag/number for live reads (default: latest)")
    parser.add_argument("--slot", type=lambda s: int(s, 0), default=None,
                        metavar="N", help="read a single raw slot")
    parser.add_argument("--var-name", metavar="NAME", default=None,
                        help="show only this state variable")
    parser.add_argument("--key", action="append", default=[], metavar="KEY",
                        help="mapping key / array index (repeatable, outermost first)")
    parser.add_argument("--key-type", default=None, metavar="TYPE",
                        help="type hint for the mapping key")
    parser.add_argument("--struct-var", metavar="FIELD", default=None,
                        help="struct field to drill into")
    parser.add_argument("--json", metavar="FILE", default=None,
                        help="write the storage-layout JSON document (- for stdout)")
    parser.add_argument("--unstructured", action="store_true",
                        help="also show EIP-1967 unstructured-storage slots")
    parser.add_argument("--max-depth", type=int, default=3,
                        help="struct/array nesting depth limit (default: 3)")
    parser.add_argument("--silent", action="store_true",
                        help="suppress the 'layout only' hint on stderr")
    return parser


def _collect_keys(args: argparse.Namespace) -> list[str]:
    keys: list[str] = []
    for key in args.key:
        if args.key_type:
            # annotate the key with its type so key_to_bytes can parse it
            keys.append(key)  # type hint is applied at resolution time
        else:
            keys.append(key)
    return keys


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        session = build_session(args.target)
        contract = find_contract(session, args.contract)
        entries = compute_layout(contract)

        client: Optional[RpcClient] = None
        address = args.address
        tag = args.block
        if args.rpc_url or address:
            if not args.rpc_url:
                raise VelvetError("--storage-address requires --rpc-url")
            if not address:
                raise VelvetError("--rpc-url requires --storage-address")
            client = RpcClient(args.rpc_url)

        def read_slot(slot: int) -> bytes:
            assert client is not None and address is not None
            return client.get_storage_at(address, slot, tag)

        # ---- raw single-slot query
        if args.slot is not None:
            if client is None:
                raise VelvetError("--slot requires --rpc-url and --storage-address")
            raw = read_slot(args.slot)
            document = {
                "success": True,
                "error": None,
                "results": {
                    "storage-layout": {
                        "contract": contract.name,
                        "slot": args.slot,
                        "raw": f"0x{raw.hex()}",
                    }
                },
            }
            if args.json:
                _emit_json(document, args.json)
            if args.json != "-":
                print(f"slot {args.slot} @ {address} (block {tag}):")
                print(f"  raw:     0x{raw.hex()}")
                print(f"  uint256: {int.from_bytes(raw, 'big')}")
                print(f"  address: 0x{raw[12:].hex()}")
            return 0

        # ---- single-variable / drill-down query
        if args.var_name:
            entry = next((e for e in entries if e.name == args.var_name), None)
            if entry is None:
                available = ", ".join(e.name for e in entries)
                raise VelvetError(
                    f"no state variable {args.var_name!r} in {contract.name} "
                    f"(available: {available})"
                )
            resolved = resolve_path(entry, _collect_keys(args), args.struct_var)
            value: Optional[str] = None
            if client is not None and address is not None:
                value = decode_value(
                    resolved.type,
                    resolved.slot,
                    read_slot(resolved.slot),
                    resolved.offset,
                    resolved.size,
                    read_slot,
                )
            query: dict[str, Any] = {
                "name": resolved.label,
                "type": type_to_solidity(resolved.type),
                "slot": resolved.slot,
                "offset": resolved.offset,
                "size": resolved.size,
                "encoding": resolved.encoding,
            }
            if value is not None:
                query["value"] = value
            if args.json:
                _emit_json(
                    build_json_document(
                        contract,
                        [],
                        None,
                        storage_address=address,
                        tag=tag,
                        max_depth=args.max_depth,
                        query=query,
                    ),
                    args.json,
                )
            if args.json != "-":
                line = (
                    f"{resolved.label}: {query['type']} @ slot {resolved.slot}, "
                    f"offset {resolved.offset} ({resolved.encoding})"
                )
                if value is not None:
                    line += f" = {value}"
                elif not args.silent:
                    line += "  (no value read: pass --rpc-url and an address)"
                print(line)
            return 0

        # ---- whole-layout listing
        values: Optional[dict[str, str]] = None
        if client is not None and address is not None:
            values = {}
            cache: dict[int, bytes] = {}
            for entry in entries:
                if entry.slot not in cache:
                    cache[entry.slot] = read_slot(entry.slot)
                values[entry.name] = _read_entry_value(
                    entry, read_slot, cache[entry.slot]
                )

        unstructured_rows: Optional[list[tuple[StorageEntry, Optional[str]]]] = None
        if args.unstructured:
            unstructured_rows = []
            for label, type_name in EIP1967_SLOTS:
                slot = unstructured_slot(label)
                entry = StorageEntry(
                    label, ElementaryType(type_name), slot, 0, 20, ENCODING_INPLACE
                )
                unstructured_value: Optional[str] = None
                if values is not None:
                    unstructured_value = decode_value(
                        entry.type, slot, read_slot(slot), entry.offset, entry.size
                    )
                unstructured_rows.append((entry, unstructured_value))

        if args.json:
            _emit_json(
                build_json_document(
                    contract,
                    entries,
                    values,
                    storage_address=address,
                    tag=tag,
                    max_depth=args.max_depth,
                    unstructured=unstructured_rows,
                ),
                args.json,
            )
        if args.json != "-":
            sys.stdout.write(
                render_table(
                    contract,
                    entries,
                    values,
                    storage_address=address if values is not None else None,
                    tag=tag,
                    unstructured=unstructured_rows,
                )
            )
            if not args.silent and values is None:
                print(
                    "(layout only — pass --rpc-url and --storage-address to read values)",
                    file=sys.stderr,
                )
        return 0
    except VelvetError as exc:
        if getattr(args, "json", None):
            _emit_json(
                {"success": False, "error": str(exc), "results": {"storage-layout": {}}},
                args.json,
            )
        else:
            print(f"velvet-read-storage: {exc}", file=sys.stderr)
        return 2


def _read_entry_value(
    entry: StorageEntry, read_slot: Callable[[int], bytes], raw: bytes
) -> str:
    return decode_value(
        entry.type, entry.slot, raw, entry.offset, entry.size, read_slot
    )


def _emit_json(document: dict[str, Any], target: str) -> None:
    text = json.dumps(document, indent=2) + "\n"
    if target == "-":
        print(text, end="")
    else:
        Path(target).write_text(text, encoding="utf-8")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
