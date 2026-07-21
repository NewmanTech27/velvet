"""Tests for the v2 companion tools (spec/printers-and-tools.md §B.5/§B.6):

- ``velvet-read-storage`` — storage layout reader (pure layout math,
  keccak slot arithmetic, mocked JSON-RPC layer, CLI);
- ``velvet-prop`` — property/unit-test generator (scenario catalog,
  generation, compilability of the emitted harness).

Layout expectations are validated against solc's own ``storageLayout``
output (the authoritative public encoding of the documented rules).
No live RPC calls: the JSON-RPC layer is mocked throughout.

Original clean-room implementation.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from velvet.compile import compile_target
from velvet.core.contract import Contract
from velvet.core.declarations import Enum, StructField, Structure
from velvet.core.types import (
    ArrayType,
    ElementaryType,
    MappingType,
    UserDefinedType,
)
from velvet.core.variables import StateVariable
from velvet.exceptions import VelvetError
from velvet.session import Velvet
from velvet.tools import prop, read_storage
from velvet.tools.read_storage import (
    EIP1967_SLOTS,
    StorageEntry,
    compute_layout,
    decode_value,
    dynamic_array_data_slot,
    encode_mapping_key,
    mapping_value_slot,
    resolve_path,
    struct_member_layout,
    unstructured_slot,
    value_type_size,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "tools"
LAYOUT_SOL = FIXTURES / "read_storage" / "Layout.sol"
PROP_TOKEN = FIXTURES / "prop" / "PropToken.sol"
GOOD_TOKEN = FIXTURES / "erc20" / "GoodToken.sol"
BAD_TOKEN = FIXTURES / "erc20" / "BadToken.sol"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _var(name, type_, *, constant=False, immutable=False):
    var = StateVariable()
    var.name = name
    var.type = type_
    var.is_constant = constant
    var.is_immutable = immutable
    return var


def _contract(name, variables, inheritance=()):
    contract = Contract(name)
    contract.state_variables = list(variables)
    contract.inheritance = list(inheritance)
    for var in variables:
        var.contract = contract
    return contract


def _layout(contract):
    return {entry.name: entry for entry in compute_layout(contract)}


UINT = lambda bits: ElementaryType(f"uint{bits}")
INT = lambda bits: ElementaryType(f"int{bits}")
BYTES_N = lambda n: ElementaryType(f"bytes{n}")
ADDRESS = ElementaryType("address")
BOOL = ElementaryType("bool")


# ---------------------------------------------------------------------------
# pure layout math (no compilation, no network)
# ---------------------------------------------------------------------------


class TestValueTypeSize:
    def test_elementary_sizes(self):
        assert value_type_size(BOOL) == 1
        assert value_type_size(ADDRESS) == 20
        assert value_type_size(ElementaryType("address payable")) == 20
        assert value_type_size(UINT(8)) == 1
        assert value_type_size(UINT(128)) == 16
        assert value_type_size(UINT(256)) == 32
        assert value_type_size(INT(64)) == 8
        assert value_type_size(BYTES_N(1)) == 1
        assert value_type_size(BYTES_N(32)) == 32
        assert value_type_size(ElementaryType("uint")) == 32  # alias

    def test_reference_types_are_not_value_types(self):
        assert value_type_size(ElementaryType("string")) is None
        assert value_type_size(ElementaryType("bytes")) is None
        assert value_type_size(ArrayType(UINT(256))) is None
        assert value_type_size(MappingType(ADDRESS, UINT(256))) is None

    def test_enum_size(self):
        small = Enum("Small")
        small.values = ["A", "B"]
        assert value_type_size(UserDefinedType(small)) == 1
        big = Enum("Big")
        big.values = [f"V{i}" for i in range(300)]
        assert value_type_size(UserDefinedType(big)) == 2

    def test_contract_type_size(self):
        assert value_type_size(UserDefinedType(Contract("Token"))) == 20


class TestPackingRules:
    def test_small_values_pack_lower_order_aligned(self):
        entries = _layout(_contract("C", [_var("a", UINT(128)), _var("b", UINT(128))]))
        assert (entries["a"].slot, entries["a"].offset) == (0, 0)
        assert (entries["b"].slot, entries["b"].offset) == (0, 16)

    def test_value_not_fitting_moves_to_next_slot(self):
        entries = _layout(
            _contract("C", [_var("a", UINT(128)), _var("b", UINT(256)), _var("c", UINT(128))])
        )
        assert (entries["a"].slot, entries["a"].offset) == (0, 0)
        assert (entries["b"].slot, entries["b"].offset) == (1, 0)
        assert (entries["c"].slot, entries["c"].offset) == (2, 0)

    def test_mixed_packing_in_one_slot(self):
        entries = _layout(
            _contract("C", [_var("f", BOOL), _var("o", ADDRESS), _var("d", INT(8))])
        )
        assert (entries["f"].slot, entries["f"].offset, entries["f"].size) == (0, 0, 1)
        assert (entries["o"].slot, entries["o"].offset, entries["o"].size) == (0, 1, 20)
        assert (entries["d"].slot, entries["d"].offset, entries["d"].size) == (0, 21, 1)

    def test_constant_and_immutable_occupy_no_storage(self):
        entries = _layout(
            _contract(
                "C",
                [
                    _var("a", UINT(256)),
                    _var("k", UINT(256), constant=True),
                    _var("i", UINT(256), immutable=True),
                    _var("b", UINT(256)),
                ],
            )
        )
        assert "k" not in entries and "i" not in entries
        assert entries["a"].slot == 0
        assert entries["b"].slot == 1

    def test_inheritance_bases_first_and_sharing_slots(self):
        base = _contract("Base", [_var("a", UINT(128))])
        derived = _contract("C", [_var("b", UINT(128))], inheritance=[base])
        entries = _layout(derived)
        # most base-ward variable first; base and derived may share a slot
        assert (entries["a"].slot, entries["a"].offset) == (0, 0)
        assert (entries["b"].slot, entries["b"].offset) == (0, 16)


class TestStructAndArrayLayout:
    def _pair(self):
        struct = Structure("Pair")
        struct.elems = [
            StructField("a", UINT(16)),
            StructField("b", UINT(16)),
            StructField("c", UINT(256)),
        ]
        return struct

    def test_struct_starts_new_slot_and_members_pack(self):
        members = {m.name: m for m in struct_member_layout(self._pair())}
        assert (members["a"].slot, members["a"].offset) == (0, 0)
        assert (members["b"].slot, members["b"].offset) == (0, 2)
        assert (members["c"].slot, members["c"].offset) == (1, 0)

    def test_struct_span_and_following_variable(self):
        entries = _layout(
            _contract(
                "C",
                [
                    _var("x", UINT(8)),
                    _var("s", UserDefinedType(self._pair())),
                    _var("y", UINT(8)),
                ],
            )
        )
        # struct starts a new slot and spans two slots; y starts a new slot
        assert entries["x"].slot == 0
        assert (entries["s"].slot, entries["s"].size) == (1, 64)
        assert entries["y"].slot == 3

    def test_static_array_packing(self):
        entries = _layout(
            _contract(
                "C",
                [
                    _var("a", ArrayType(UINT(8), 10)),  # 10 per slot -> 1
                    _var("b", ArrayType(BYTES_N(5), 8)),  # 6 per slot -> 2
                    _var("c", ArrayType(UINT(256), 2)),  # 1 per slot -> 2
                    _var("d", ArrayType(BYTES_N(20), 2)),  # >16 bytes -> 2
                    _var("e", ArrayType(ArrayType(UINT(8), 2), 3)),  # 3 * 1
                ],
            )
        )
        assert (entries["a"].slot, entries["a"].size) == (0, 32)
        assert (entries["b"].slot, entries["b"].size) == (1, 64)
        assert (entries["c"].slot, entries["c"].size) == (3, 64)
        assert (entries["d"].slot, entries["d"].size) == (5, 64)
        assert (entries["e"].slot, entries["e"].size) == (7, 96)

    def test_mapping_and_dynamic_array_take_full_slots(self):
        entries = _layout(
            _contract(
                "C",
                [
                    _var("m", MappingType(ADDRESS, UINT(256))),
                    _var("a", ArrayType(UINT(24))),  # dynamic
                    _var("s", ElementaryType("string")),
                    _var("b", ElementaryType("bytes")),
                ],
            )
        )
        assert entries["m"].slot == 0 and entries["m"].encoding == "mapping"
        assert entries["a"].slot == 1 and entries["a"].encoding == "dynamic_array"
        assert entries["s"].slot == 2 and entries["s"].encoding == "bytes"
        assert entries["b"].slot == 3 and entries["b"].encoding == "bytes"


# ---------------------------------------------------------------------------
# keccak slot arithmetic and key encoding
# ---------------------------------------------------------------------------


class TestSlotMath:
    def test_mapping_slot_matches_documented_example(self):
        # Solidity docs: data[4][9] for `mapping(uint => mapping(uint => S)) data;`
        # at slot 1 is keccak256(uint256(9) . keccak256(uint256(4) . uint256(1))).
        inner = mapping_value_slot((4).to_bytes(32, "big"), 1)
        outer = mapping_value_slot((9).to_bytes(32, "big"), inner)
        assert outer == mapping_value_slot(
            encode_mapping_key(UINT(256), "9"),
            mapping_value_slot(encode_mapping_key(UINT(256), "4"), 1),
        )
        # ... and the struct member c (third member, packed after a/b) is +1
        assert outer + 1 != outer

    def test_dynamic_array_data_slot_is_keccak_of_head(self):
        from velvet.tools.common import keccak256

        assert dynamic_array_data_slot(5) == int.from_bytes(
            keccak256((5).to_bytes(32, "big")), "big"
        )

    def test_unstructured_slots_match_eip1967(self):
        # publicly known EIP-1967 slot constants
        known = {
            "eip1967.proxy.implementation": "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            "eip1967.proxy.admin": "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
            "eip1967.proxy.beacon": "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
        }
        for label, expected in known.items():
            assert f"{unstructured_slot(label):064x}" == expected
        assert [label for label, _ in EIP1967_SLOTS] == list(known)

    def test_encode_address_key_left_padded(self):
        key = encode_mapping_key(ADDRESS, "0x" + "11" * 20)
        assert key == bytes(12) + b"\x11" * 20

    def test_encode_uint_key(self):
        assert encode_mapping_key(UINT(256), "42") == (42).to_bytes(32, "big")
        assert encode_mapping_key(UINT(8), "0xff") == (255).to_bytes(32, "big")

    def test_encode_uint_key_range_checked(self):
        with pytest.raises(VelvetError):
            encode_mapping_key(UINT(8), "256")

    def test_encode_negative_int_key_twos_complement(self):
        key = encode_mapping_key(INT(8), "-2")
        assert key == b"\xff" * 31 + b"\xfe"
        with pytest.raises(VelvetError):
            encode_mapping_key(INT(8), "-129")

    def test_encode_bool_key(self):
        assert encode_mapping_key(BOOL, "true")[-1] == 1
        assert encode_mapping_key(BOOL, "false")[-1] == 0
        with pytest.raises(VelvetError):
            encode_mapping_key(BOOL, "yes")

    def test_encode_bytesn_key_right_padded(self):
        key = encode_mapping_key(BYTES_N(5), "0x0102030405")
        assert key == b"\x01\x02\x03\x04\x05" + bytes(27)
        with pytest.raises(VelvetError):
            encode_mapping_key(BYTES_N(5), "0x0102")  # wrong length

    def test_encode_string_and_bytes_keys_unpadded(self):
        assert encode_mapping_key(ElementaryType("string"), "hello") == b"hello"
        assert encode_mapping_key(ElementaryType("bytes"), "0xdead") == b"\xde\xad"

    def test_encode_enum_key_by_name_or_index(self):
        enum = Enum("Level")
        enum.values = ["Low", "Mid", "High"]
        assert encode_mapping_key(UserDefinedType(enum), "Mid") == (1).to_bytes(32, "big")
        assert encode_mapping_key(UserDefinedType(enum), "2") == (2).to_bytes(32, "big")
        with pytest.raises(VelvetError):
            encode_mapping_key(UserDefinedType(enum), "5")


class TestResolvePath:
    def test_nested_mapping_then_struct_member(self):
        struct = Structure("Pair")
        struct.elems = [
            StructField("a", UINT(16)),
            StructField("b", UINT(16)),
            StructField("c", UINT(256)),
        ]
        nested = MappingType(
            ADDRESS, MappingType(UINT(256), UserDefinedType(struct))
        )
        entry = StorageEntry("data", nested, 4, 0, 32, "mapping")
        resolved = resolve_path(entry, ["0x" + "11" * 20, "4"], "c")
        inner = mapping_value_slot(bytes(12) + b"\x11" * 20, 4)
        head = mapping_value_slot((4).to_bytes(32, "big"), inner)
        assert resolved.slot == head + 1  # member c is one slot into the struct
        assert resolved.offset == 0
        assert resolved.label.endswith("[4].c")

    def test_static_array_index_bounds(self):
        entry = StorageEntry("stat", ArrayType(BYTES_N(5), 8), 6, 0, 64)
        resolved = resolve_path(entry, ["7"], None)
        # 6 elements per slot: index 7 -> slot 7, byte offset 5
        assert (resolved.slot, resolved.offset) == (7, 5)
        with pytest.raises(VelvetError):
            resolve_path(entry, ["8"], None)

    def test_dynamic_array_index(self):
        entry = StorageEntry("dyn", ArrayType(UINT(24)), 5, 0, 32, "dynamic_array")
        resolved = resolve_path(entry, ["3"], None)
        base = dynamic_array_data_slot(5)
        # 10 uint24 per slot: index 3 -> base + 0, byte offset 9
        assert (resolved.slot, resolved.offset) == (base, 9)

    def test_struct_var_requires_struct(self):
        entry = StorageEntry("u", UINT(256), 0, 0, 32)
        with pytest.raises(VelvetError):
            resolve_path(entry, [], "field")


# ---------------------------------------------------------------------------
# layout validated against solc's own storageLayout output
# ---------------------------------------------------------------------------


class TestLayoutOracle:
    def test_matches_solc_storage_layout(self):
        from velvet.compile.solc_runner import (
            build_standard_json_input,
            run_solc_standard_json,
        )
        from velvet.compile.versions import select_version

        source = LAYOUT_SOL.read_text(encoding="utf-8")
        version = select_version([source])
        std_input = build_standard_json_input({"Layout.sol": source})
        std_input["settings"]["outputSelection"]["*"]["*"] = ["storageLayout"]
        output = run_solc_standard_json(std_input, version)
        oracle = output.raw["contracts"]["Layout.sol"]["Layout"]["storageLayout"]

        session = Velvet(str(LAYOUT_SOL))
        contract = session.get_contract_from_name("Layout")
        mine = {entry.name: entry for entry in compute_layout(contract)}

        assert {entry["label"] for entry in oracle["storage"]} == set(mine)
        for entry in oracle["storage"]:
            expected_bytes = int(oracle["types"][entry["type"]]["numberOfBytes"])
            got = mine[entry["label"]]
            assert (got.slot, got.offset, got.size) == (
                int(entry["slot"]),
                entry["offset"],
                expected_bytes,
            ), f"layout mismatch for {entry['label']}"


# ---------------------------------------------------------------------------
# JSON-RPC layer (mocked — no live calls)
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestRpcClient:
    def test_get_storage_at_request_and_parsing(self, monkeypatch):
        captured = {}

        def fake_urlopen(request, timeout=0):
            captured["url"] = request.full_url
            captured["payload"] = json.loads(request.data.decode("utf-8"))
            slot = captured["payload"]["params"][1]
            return _FakeResponse(
                {"jsonrpc": "2.0", "id": 1, "result": "0x" + f"{int(slot, 16):064x}"}
            )

        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        client = read_storage.RpcClient("http://node.local:8545")
        data = client.get_storage_at("0x" + "22" * 20, 7, "latest")
        assert captured["url"] == "http://node.local:8545"
        assert captured["payload"]["method"] == "eth_getStorageAt"
        assert captured["payload"]["params"] == ["0x" + "22" * 20, "0x7", "latest"]
        assert captured["payload"]["jsonrpc"] == "2.0"
        assert data == (7).to_bytes(32, "big")

    def test_rpc_error_raises(self, monkeypatch):
        def fake_urlopen(request, timeout=0):
            return _FakeResponse(
                {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "boom"}}
            )

        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        client = read_storage.RpcClient("http://node.local:8545")
        with pytest.raises(VelvetError, match="boom"):
            client.get_storage_at("0x" + "22" * 20, 0, "latest")

    def test_connection_failure_raises(self, monkeypatch):
        import urllib.error

        def fake_urlopen(request, timeout=0):
            raise urllib.error.URLError("refused")

        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        client = read_storage.RpcClient("http://node.local:8545")
        with pytest.raises(VelvetError, match="RPC request"):
            client.get_storage_at("0x" + "22" * 20, 0, "latest")


class _FakeRpcClient:
    """In-memory RpcClient stub driven by a {slot: bytes} state."""

    state: dict[int, bytes] = {}

    def __init__(self, url, timeout=30.0):
        self.url = url

    def get_storage_at(self, address, slot, block_tag):
        return self.state.get(slot, bytes(32))


@pytest.fixture
def fake_rpc(monkeypatch):
    _FakeRpcClient.state = {}
    monkeypatch.setattr(read_storage, "RpcClient", _FakeRpcClient)
    return _FakeRpcClient.state


READ_ADDRESS = "0x" + "33" * 20


def _layout_session():
    session = Velvet(str(LAYOUT_SOL))
    return session, session.get_contract_from_name("Layout")


class TestReadStorageValues:
    """CLI value decoding with a mocked node (Layout fixture)."""

    def test_table_values(self, fake_rpc, capsys):
        # slot 0: x (uint128 @0) = 5, y (uint128 @16) = 7
        fake_rpc[0] = ((7 << 128) | 5).to_bytes(32, "big")
        # slot 1: u = 42
        fake_rpc[1] = (42).to_bytes(32, "big")
        # slot 8: short string "hello" (data left aligned, low byte = 2*len)
        fake_rpc[8] = b"hello" + bytes(26) + bytes([10])
        # slot 10: flag=true, admin=0x11.., delta=-2, level=2
        admin_int = int("11" * 20, 16)
        head10 = 1 | (admin_int << 8) | (0xFE << (21 * 8)) | (2 << (22 * 8))
        fake_rpc[10] = head10.to_bytes(32, "big")
        code = read_storage.main(
            [
                str(LAYOUT_SOL),
                "Layout",
                "--rpc-url",
                "http://node",
                "--storage-address",
                READ_ADDRESS,
            ]
        )
        assert code == 0
        out = capsys.readouterr().out
        assert f"values at {READ_ADDRESS}" in out

        import re

        rows = {}
        for line in out.splitlines():
            cells = re.split(r"\s{2,}", line.strip())
            if len(cells) >= 6 and cells[0].isdigit():
                rows[cells[4]] = cells
        assert rows["x"][5] == "5"
        assert rows["y"][5] == "7"
        assert rows["u"][5] == "42"
        assert '"hello"' in rows["label"][5]
        assert rows["flag"][5] == "true"
        assert rows["admin"][5] == "0x" + "11" * 20
        assert rows["delta"][5] == "-2"
        assert "High (2)" in rows["level"][5]
        assert "length" in rows["dyn"][5]  # dynamic array head shows the length
        assert rows["data"][5] == "-"  # mapping head not decodable

    def test_single_value_query(self, fake_rpc, capsys):
        fake_rpc[1] = (42).to_bytes(32, "big")
        code = read_storage.main(
            [
                str(LAYOUT_SOL),
                "Layout",
                "--rpc-url",
                "http://node",
                "--storage-address",
                READ_ADDRESS,
                "--var-name",
                "u",
            ]
        )
        assert code == 0
        out = capsys.readouterr().out
        assert "u: uint256 @ slot 1, offset 0 (inplace) = 42" in out

    def test_mapping_drill_down_reads_computed_slot(self, fake_rpc, capsys):
        session, contract = _layout_session()
        entries = {e.name: e for e in compute_layout(contract)}
        resolved = resolve_path(
            entries["data"], ["0x" + "ab" * 20, "4"], "c"
        )
        fake_rpc[resolved.slot] = (99).to_bytes(32, "big")
        code = read_storage.main(
            [
                str(LAYOUT_SOL),
                "Layout",
                "--rpc-url",
                "http://node",
                "--storage-address",
                READ_ADDRESS,
                "--var-name",
                "data",
                "--key",
                "0x" + "ab" * 20,
                "--deep-key",
                "4",
                "--struct-var",
                "c",
            ]
        )
        assert code == 0
        out = capsys.readouterr().out
        assert f"data[0x{'ab' * 20}][4].c: uint256 @ slot {resolved.slot}" in out
        assert "= 99" in out

    def test_raw_slot_read(self, fake_rpc, capsys):
        fake_rpc[3] = (0x1234).to_bytes(32, "big")
        code = read_storage.main(
            [
                str(LAYOUT_SOL),
                "Layout",
                "--rpc-url",
                "http://node",
                "--storage-address",
                READ_ADDRESS,
                "--slot",
                "3",
            ]
        )
        assert code == 0
        out = capsys.readouterr().out
        assert "slot 3 @ " + READ_ADDRESS in out
        assert "uint256: 4660" in out

    def test_historical_block_tag(self, monkeypatch, capsys):
        captured = {}

        class CapturingClient:
            def __init__(self, url, timeout=30.0):
                pass

            def get_storage_at(self, address, slot, block_tag):
                captured["block"] = block_tag
                return bytes(32)

        monkeypatch.setattr(read_storage, "RpcClient", CapturingClient)
        code = read_storage.main(
            [
                str(LAYOUT_SOL),
                "Layout",
                "--rpc-url",
                "http://node",
                "--storage-address",
                READ_ADDRESS,
                "--block",
                "12345",
                "--var-name",
                "u",
            ]
        )
        assert code == 0
        assert captured["block"] == hex(12345)

    def test_unstructured_slots_read(self, fake_rpc, capsys):
        impl = unstructured_slot("eip1967.proxy.implementation")
        fake_rpc[impl] = (int("44" * 20, 16)).to_bytes(32, "big")
        code = read_storage.main(
            [
                str(LAYOUT_SOL),
                "Layout",
                "--rpc-url",
                "http://node",
                "--storage-address",
                READ_ADDRESS,
                "--unstructured",
            ]
        )
        assert code == 0
        out = capsys.readouterr().out
        assert "(unstructured) eip1967.proxy.implementation" in out
        assert "0x" + "44" * 20 in out


class TestValueDecoding:
    """decode_value is pure for slot-resident types (no RPC needed)."""

    def _slot(self, value: int) -> bytes:
        return value.to_bytes(32, "big")

    def test_signed_int_decoding(self):
        slot = self._slot((1 << 256) - 2)  # -2 in two's complement
        assert decode_value(INT(256), 0, slot, 0, 32) == "-2"
        slot8 = self._slot(0xFE)
        assert decode_value(INT(8), 0, slot8, 0, 1) == "-2"

    def test_packed_regions_do_not_bleed(self):
        # x = 5 at offset 0, y = 7 at offset 16 in one slot
        slot = self._slot((7 << 128) | 5)
        assert decode_value(UINT(128), 0, slot, 0, 16) == "5"
        assert decode_value(UINT(128), 0, slot, 16, 16) == "7"

    def test_bool_address_bytesn(self):
        assert decode_value(BOOL, 0, self._slot(1), 0, 1) == "true"
        assert decode_value(BOOL, 0, self._slot(0), 0, 1) == "false"
        addr_slot = self._slot(int("ab" * 20, 16))
        assert decode_value(ADDRESS, 0, addr_slot, 0, 20) == "0x" + "ab" * 20
        # bytesN values are stored lower-order aligned in their slot region
        bytes5_slot = bytes(27) + b"\x01\x02\x03\x04\x05"
        assert decode_value(BYTES_N(5), 0, bytes5_slot, 0, 5) == "0x0102030405"

    def test_enum_decoding(self):
        enum = Enum("Level")
        enum.values = ["Low", "Mid", "High"]
        type_ = UserDefinedType(enum)
        assert decode_value(type_, 0, self._slot(2), 0, 1) == "High (2)"
        assert "invalid" in decode_value(type_, 0, self._slot(9), 0, 1)

    def test_short_and_long_bytes(self):
        short = b"hi" + bytes(29) + bytes([4])  # length 2 -> low byte 4
        read = lambda slot: bytes(32)
        assert (
            decode_value(ElementaryType("string"), 0, short, 0, 32, read) == '"hi"'
        )
        # long form: length*2+1 = 65 -> 32 bytes at keccak(slot)
        long_head = self._slot(65)
        payload = b"\xab" * 32
        read_long = lambda slot: payload
        assert (
            decode_value(ElementaryType("bytes"), 0, long_head, 0, 32, read_long)
            == "0x" + "ab" * 32
        )


# ---------------------------------------------------------------------------
# velvet-read-storage CLI (offline behavior)
# ---------------------------------------------------------------------------


class TestReadStorageCLI:
    def test_layout_table_without_rpc(self, capsys):
        code = read_storage.main([str(LAYOUT_SOL), "Layout"])
        assert code == 0
        out = capsys.readouterr().out
        assert "Storage layout of Layout:" in out
        assert "Slot" in out and "Offset" in out and "Type" in out
        # inherited variables come first and share slot 0
        lines = [ln for ln in out.splitlines() if "uint128" in ln]
        assert any(ln.rstrip().endswith("x") for ln in lines)
        assert any(ln.rstrip().endswith("y") for ln in lines)
        # constant/immutable are not listed
        assert "FIXED" not in out and "deployed" not in out

    def test_var_name_restricts_listing(self, capsys):
        code = read_storage.main([str(LAYOUT_SOL), "Layout", "--var-name", "u"])
        assert code == 0
        out = capsys.readouterr().out
        assert "u: uint256 @ slot 1, offset 0 (inplace)" in out
        assert "no value read" in out  # offline hint

    def test_var_name_unknown_variable_exit_2(self, capsys):
        code = read_storage.main([str(LAYOUT_SOL), "Layout", "--var-name", "nope"])
        assert code == 2
        assert "no state variable" in capsys.readouterr().err

    def test_key_requires_var_name(self, capsys):
        code = read_storage.main([str(LAYOUT_SOL), "Layout", "--key", "1"])
        assert code == 2
        assert "--key requires --var-name" in capsys.readouterr().err

    def test_value_requires_rpc_url(self, capsys):
        code = read_storage.main([str(LAYOUT_SOL), "Layout", "--value"])
        assert code == 2
        assert "--rpc-url" in capsys.readouterr().err

    def test_rpc_url_requires_address(self, capsys):
        code = read_storage.main([str(LAYOUT_SOL), "Layout", "--rpc-url", "http://x"])
        assert code == 2
        assert "address" in capsys.readouterr().err

    def test_unknown_contract_exit_2(self, capsys):
        code = read_storage.main([str(LAYOUT_SOL), "Nope"])
        assert code == 2
        assert "not found" in capsys.readouterr().err

    def test_json_layout(self, capsys):
        code = read_storage.main([str(LAYOUT_SOL), "Layout", "--json", "-"])
        assert code == 0
        document = json.loads(capsys.readouterr().out)
        assert document["success"] is True
        layout = document["results"]["storage-layout"]
        assert layout["contract"] == "Layout"
        variables = {v["name"]: v for v in layout["variables"]}
        assert (variables["x"]["slot"], variables["x"]["offset"]) == (0, 0)
        assert (variables["y"]["slot"], variables["y"]["offset"]) == (0, 16)
        assert variables["data"]["encoding"] == "mapping"
        assert variables["dyn"]["encoding"] == "dynamic_array"
        # struct members are nested (bounded by --max-depth)
        members = {m["name"]: m for m in variables["pair"]["members"]}
        assert (members["c"]["slot"], members["c"]["offset"]) == (1, 0)

    def test_json_on_error(self, capsys):
        code = read_storage.main([str(LAYOUT_SOL), "Nope", "--json", "-"])
        assert code == 2
        document = json.loads(capsys.readouterr().out)
        assert document["success"] is False
        assert "not found" in document["error"]

    def test_console_script(self):
        result = subprocess.run(
            [sys.executable, "-m", "velvet.tools.read_storage", str(LAYOUT_SOL), "Layout"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Storage layout of Layout:" in result.stdout


# ---------------------------------------------------------------------------
# velvet-prop
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def prop_session():
    return Velvet(str(PROP_TOKEN))


@pytest.fixture(scope="module")
def prop_contract(prop_session):
    return prop_session.get_contract_from_name("PropToken")


class TestScenarioCatalog:
    def test_list_scenarios(self, capsys):
        code = prop.main(["--list-scenarios"])
        assert code == 0
        out = capsys.readouterr().out
        for name in (
            "Transferable",
            "Pausable",
            "NotMintable",
            "NotMintableNotBurnable",
            "NotBurnable",
            "Burnable",
        ):
            assert name in out
        # documented catalog entries
        assert "The address 0x0 should not receive tokens." in out
        assert "The total supply does not decrease (except via burn)." in out
        assert "Cannot transfer (while paused)." in out

    def test_scenario_bundles(self):
        assert len(prop.get_scenario("Transferable").properties) == 11
        assert len(prop.get_scenario("Pausable").properties) == 15
        assert len(prop.get_scenario("NotMintable").properties) == 12
        assert len(prop.get_scenario("NotMintableNotBurnable").properties) == 12
        assert len(prop.get_scenario("NotBurnable").properties) == 12
        assert len(prop.get_scenario("Burnable").properties) == 12
        # default scenario is Transferable
        assert prop.get_scenario("transferable").name == "Transferable"

    def test_unknown_scenario(self):
        with pytest.raises(VelvetError, match="unknown scenario"):
            prop.get_scenario("Reentrancy")


class TestPropertySelection:
    def test_all_properties_apply_to_prop_token(self, prop_contract):
        applicable, skipped = prop.select_properties(
            prop_contract, prop.get_scenario("Pausable")
        )
        assert len(applicable) == 15
        assert skipped == []

    def test_missing_surface_skips_properties(self):
        session = Velvet(str(BAD_TOKEN))
        contract = session.get_contract_from_name("BadToken")
        applicable, skipped = prop.select_properties(
            contract, prop.get_scenario("Transferable")
        )
        skipped_keys = {p.key for p, _ in skipped}
        # BadToken has no allowance(): allowance-related properties are skipped
        assert "allowance_can_be_changed" in skipped_keys
        assert prop.P1 not in applicable

    def test_burnable_requires_burn(self, prop_contract):
        prop.validate_scenario_surface(prop_contract, prop.get_scenario("Burnable"))
        session = Velvet(str(GOOD_TOKEN))
        good = session.get_contract_from_name("GoodToken")
        with pytest.raises(VelvetError, match="burn"):
            prop.validate_scenario_surface(good, prop.get_scenario("Burnable"))

    def test_pausable_requires_pause(self):
        session = Velvet(str(GOOD_TOKEN))
        good = session.get_contract_from_name("GoodToken")
        with pytest.raises(VelvetError, match="pause"):
            prop.validate_scenario_surface(good, prop.get_scenario("Pausable"))


class TestGenerate:
    def _generate(self, tmp_path, scenario="Transferable", target=None, name="PropToken"):
        source = target or PROP_TOKEN
        work = tmp_path / "proj"
        work.mkdir()
        import shutil

        copied = work / Path(source).name
        shutil.copy(source, copied)
        session = Velvet(str(copied))
        contract = session.get_contract_from_name(name)
        result = prop.generate(session, contract, prop.get_scenario(scenario), work)
        return result, work

    def test_transferable_artifacts(self, tmp_path):
        result, work = self._generate(tmp_path)
        name = "PropToken"
        expected = {
            f"contracts/crytic/Properties{name}.sol",
            f"contracts/crytic/Test{name}.sol",
            "contracts/crytic/interfaces.sol",
            "echidna_config.yaml",
            f"migrations/1_Test{name}.js",
            f"test/crytic/InitializationTest{name}.js",
            f"test/crytic/Test{name}.js",
        }
        assert {str(p.relative_to(work)) for p in result.files} == expected
        properties = (work / f"contracts/crytic/Properties{name}.sol").read_text()
        # 11 documented Transferable properties as echidna predicates
        assert properties.count("function echidna_") == 11
        assert "The address 0x0 should not receive tokens." in properties
        assert "abstract contract PropertiesPropToken" in properties
        harness = (work / f"contracts/crytic/Test{name}.sol").read_text()
        assert f"contract Test{name} is Properties{name}" in harness
        assert "token = new PropToken(0);" in harness  # TODO placeholder args
        assert "crytic_owner" in harness and "crytic_attacker" in harness
        assert "fuzz_transfer" in harness and "fuzz_approve" in harness
        # interfaces.sol exposes the external surface
        interfaces = (work / "contracts/crytic/interfaces.sol").read_text()
        assert "interface IPropToken" in interfaces
        # echidna config: property mode + the three actors as senders
        config = (work / "echidna_config.yaml").read_text()
        assert "testMode: property" in config
        for _, address in prop.ACTORS:
            assert address in config
        # truffle artifacts reference the harness
        migration = (work / f"migrations/1_Test{name}.js").read_text()
        assert f'artifacts.require("Test{name}")' in migration
        init_test = (work / f"test/crytic/InitializationTest{name}.js").read_text()
        assert "total supply correctly initialized" in init_test
        assert "balances initialized" in init_test
        assert "positive balance" in init_test
        scenario_test = (work / f"test/crytic/Test{name}.js").read_text()
        assert "echidna_transfer_works" in scenario_test

    def test_generated_solidity_compiles(self, tmp_path):
        _, work = self._generate(tmp_path)
        names = sorted(
            name
            for a in compile_target(str(work), with_abi_bytecode=True)
            for name in a.abis
        )
        assert names == [
            "IPropToken",
            "PropToken",
            "PropertiesPropToken",
            "TestPropToken",
        ]

    def test_pausable_scenario_compiles(self, tmp_path):
        _, work = self._generate(tmp_path, scenario="Pausable")
        harness = (work / "contracts/crytic/TestPropToken.sol").read_text()
        assert "fuzz_pause" in harness
        assert "token.paused()" in harness
        properties = (work / "contracts/crytic/PropertiesPropToken.sol").read_text()
        assert "Cannot transfer (while paused)." in properties
        assert properties.count("function echidna_") == 15
        compile_target(str(work))

    def test_burnable_scenario(self, tmp_path):
        _, work = self._generate(tmp_path, scenario="Burnable")
        harness = (work / "contracts/crytic/TestPropToken.sol").read_text()
        assert "fuzz_burn" in harness
        properties = (work / "contracts/crytic/PropertiesPropToken.sol").read_text()
        assert "burn_used" in properties
        compile_target(str(work))

    def test_external_target_is_flattened(self, tmp_path):
        # target outside the output tree -> self-contained flattened copy
        out = tmp_path / "export"
        session = Velvet(str(PROP_TOKEN))
        contract = session.get_contract_from_name("PropToken")
        result = prop.generate(
            session, contract, prop.get_scenario("Transferable"), out
        )
        assert result.flattened_target
        flattened = out / "contracts/crytic/PropTokenTarget.sol"
        assert flattened.is_file()
        assert "contract PropToken" in flattened.read_text()
        properties = (out / "contracts/crytic/PropertiesPropToken.sol").read_text()
        assert 'import "./PropTokenTarget.sol";' in properties
        compile_target(str(out))

    def test_next_steps_text(self, tmp_path, capsys):
        self._generate(tmp_path)
        code = prop.main(
            [str(PROP_TOKEN), "PropToken", "--dir", str(tmp_path / "cli-out")]
        )
        assert code == 0
        out = capsys.readouterr().out
        assert "Next steps:" in out
        assert "truffle test" in out
        assert "echidna-test" in out


class TestPropCLI:
    def test_unknown_scenario_exit_2(self, capsys):
        code = prop.main([str(PROP_TOKEN), "PropToken", "--scenario", "Nope"])
        assert code == 2
        assert "unknown scenario" in capsys.readouterr().err

    def test_burnable_without_burn_exit_2(self, capsys):
        code = prop.main([str(GOOD_TOKEN), "GoodToken", "--scenario", "Burnable"])
        assert code == 2
        assert "burn(address)" in capsys.readouterr().err

    def test_unknown_contract_exit_2(self, capsys):
        code = prop.main([str(PROP_TOKEN), "Nope"])
        assert code == 2
        assert "not found" in capsys.readouterr().err

    def test_missing_target_exit_2(self, capsys):
        code = prop.main([])
        assert code == 2
        assert "TARGET is required" in capsys.readouterr().err

    def test_console_script_list(self):
        result = subprocess.run(
            [sys.executable, "-m", "velvet.tools.prop", "--list-scenarios"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Transferable" in result.stdout

    def test_console_script_generate(self, tmp_path):
        work = tmp_path / "proj"
        work.mkdir()
        import shutil

        shutil.copy(PROP_TOKEN, work / "PropToken.sol")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "velvet.tools.prop",
                str(work / "PropToken.sol"),
                "PropToken",
                "--dir",
                str(work),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Next steps:" in result.stdout
        assert (work / "contracts/crytic/TestPropToken.sol").is_file()
