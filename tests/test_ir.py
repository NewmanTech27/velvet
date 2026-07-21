"""IR conversion tests: op shapes on fixture contracts (architecture.md §6.4).

Original clean-room implementation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from velvet.compile import compile_target
from velvet.ir import (
    Assignment,
    Binary,
    Condition,
    Delete,
    EventCall,
    HighLevelCall,
    Index,
    InitArray,
    InternalCall,
    LibraryCall,
    LowLevelCall,
    Member,
    NewArray,
    NewContract,
    NewStructure,
    Push,
    Return,
    Send,
    SolidityCall,
    Transfer,
    TypeConversion,
    Unpack,
    convert_unit,
)
from velvet.ir.variables import ReferenceVariable, TemporaryVariable, TupleVariable
from velvet.parsing import parse_artifacts

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _parse(path: Path):
    artifacts = compile_target(str(path))[0]
    unit = parse_artifacts(artifacts)
    convert_unit(unit)
    return unit


@pytest.fixture(scope="module")
def ops_unit():
    return _parse(FIXTURES / "ir" / "Ops.sol")


@pytest.fixture(scope="module")
def calls_unit():
    return _parse(FIXTURES / "parsing" / "Calls.sol")


def _ops_of(unit, contract: str, signature: str, kinds: tuple) -> list:
    c = unit.get_contract_from_name(contract)
    f = c.get_function_from_signature(signature)
    found = []
    for node in f.nodes:
        found.extend(op for op in node.ir_operations if isinstance(op, kinds))
    return found


def _all_ops(unit, kinds: tuple) -> list:
    found = []
    for f in unit.functions_and_modifiers:
        for node in f.nodes:
            found.extend(op for op in node.ir_operations if isinstance(op, kinds))
    return found


# ------------------------------------------------------------------- shapes
class TestBasicShapes:
    def test_binary_and_assignment_for_plain_ops(self, ops_unit):
        ops = _ops_of(ops_unit, "Ops", "arithmetic(uint256,uint256)", (Binary,))
        assert ops, "expected Binary ops for a + b"
        assert str(ops[0]) == "TMP_0 = a + b"

    def test_compound_assignment_is_binary_plus_assignment(self, ops_unit):
        f = ops_unit.get_contract_from_name("Ops").get_function_from_signature(
            "arithmetic(uint256,uint256)"
        )
        texts = [str(op) for node in f.nodes for op in node.ir_operations]
        # c += 1 -> TMP = c + 1 ; c := TMP
        assert any(t.startswith("TMP_") and t.endswith("= c + 1") for t in texts)
        assert any(t.startswith("c := TMP_") for t in texts)

    def test_increment_lowering(self, ops_unit):
        f = ops_unit.get_contract_from_name("Ops").get_function_from_signature(
            "arithmetic(uint256,uint256)"
        )
        texts = [str(op) for node in f.nodes for op in node.ir_operations]
        # c++ -> TMP_old := c ; TMP = c + 1 ; c := TMP
        assert any("= c + 1" in t for t in texts)
        assert any(t.startswith("c := TMP_") for t in texts)

    def test_ternary_is_lowered_by_parser(self, ops_unit):
        f = ops_unit.get_contract_from_name("Ops").get_function_from_signature(
            "arithmetic(uint256,uint256)"
        )
        kinds = [op for node in f.nodes for op in node.ir_operations]
        assert any(isinstance(op, Condition) for op in kinds)

    def test_return_op(self, ops_unit):
        ops = _ops_of(ops_unit, "Ops", "arithmetic(uint256,uint256)", (Return,))
        assert len(ops) == 1
        assert str(ops[0]).startswith("RETURN")


class TestDereferenceShapes:
    def test_push_op(self, ops_unit):
        ops = _ops_of(ops_unit, "Ops", "arrays(uint256)", (Push,))
        assert ops
        assert str(ops[0]).startswith("PUSH values")

    def test_index_ref_and_write(self, ops_unit):
        ops = _ops_of(ops_unit, "Ops", "arrays(uint256)", (Index,))
        assert ops
        ref = ops[0].lvalue
        assert isinstance(ref, ReferenceVariable)
        assert str(ops[0]).startswith("REF_0 -> values")

    def test_delete_op(self, ops_unit):
        ops = _ops_of(ops_unit, "Ops", "arrays(uint256)", (Delete,))
        assert len(ops) == 1
        assert "DELETE" in str(ops[0])

    def test_new_array(self, ops_unit):
        ops = _ops_of(ops_unit, "Ops", "arrays(uint256)", (NewArray,))
        assert len(ops) == 1
        assert "NEW_ARRAY" in str(ops[0])

    def test_struct_member_chain(self, ops_unit):
        ops = _ops_of(ops_unit, "Ops", "structsAndMaps(address,uint256)", (Member,))
        assert any(op.member_name == "amount" for op in ops)
        assert any("-> orders" in str(op) or "orders" in str(op) for op in _ops_of(
            ops_unit, "Ops", "structsAndMaps(address,uint256)", (Index,)
        ))

    def test_new_structure(self, ops_unit):
        ops = _ops_of(ops_unit, "Ops", "structsAndMaps(address,uint256)", (NewStructure,))
        assert len(ops) == 1
        assert "NEW_STRUCTURE Order" in str(ops[0])


class TestCallShapes:
    def test_library_call_receiver_first(self, ops_unit):
        ops = _ops_of(ops_unit, "Ops", "libraryUse(uint256)", (LibraryCall,))
        assert len(ops) == 1
        op = ops[0]
        assert op.is_library_call
        assert op.function is not None and op.function.name == "add"
        # receiver (x) is the first argument
        assert op.arguments[0].name == "x"
        assert "TMP_0 = LIBRARY_CALL dest:Counter function:add args:[x, 2]" == str(op)

    def test_transfer_send_lowlevel(self, ops_unit):
        money = _ops_of(ops_unit, "Ops", "money(address payable,uint256)", (Transfer, Send, LowLevelCall))
        kinds = {type(op) for op in money}
        assert Transfer in kinds and Send in kinds and LowLevelCall in kinds
        transfer = next(op for op in money if isinstance(op, Transfer))
        assert str(transfer) == "TRANSFER dest:to amount:amount"
        low = next(op for op in money if isinstance(op, LowLevelCall))
        assert low.function_name == "call"
        assert low.call_value is not None and low.call_gas is not None
        assert isinstance(low.lvalue, TupleVariable)

    def test_unpack_after_lowlevel(self, ops_unit):
        ops = _ops_of(ops_unit, "Ops", "money(address payable,uint256)", (Unpack,))
        assert ops and isinstance(ops[0].tuple_variable, TupleVariable)

    def test_solidity_call_require(self, ops_unit):
        ops = _ops_of(ops_unit, "Ops", "emitAndRequire(uint256)", (SolidityCall,))
        assert ops[0].function.name == "require"
        assert "SOLIDITY_CALL require" in str(ops[0])

    def test_event_call(self, ops_unit):
        ops = _ops_of(ops_unit, "Ops", "emitAndRequire(uint256)", (EventCall,))
        assert len(ops) == 1
        assert ops[0].event.name == "Deposited"
        assert str(ops[0]).startswith("EVENT_CALL Deposited")

    def test_type_conversion(self, ops_unit):
        ops = _ops_of(ops_unit, "Ops", "typeplay(address)", (TypeConversion,))
        assert ops
        assert "CONVERT" in str(ops[0])

    def test_new_contract(self, ops_unit):
        ops = _all_ops(ops_unit, (NewContract,))
        assert len(ops) == 1
        assert "NEW_CONTRACT Ops" in str(ops[0])

    def test_external_call_high_level(self, ops_unit):
        ops = _ops_of(ops_unit, "Factory", "useIt(uint256,uint256)", (HighLevelCall,))
        assert len(ops) == 1
        op = ops[0]
        assert op.function_name == "arithmetic"
        assert op.function is not None and op.function.name == "arithmetic"
        assert "HIGH_LEVEL_CALL dest:deployed function:arithmetic" in str(op)

    def test_internal_call(self, ops_unit):
        ops = _ops_of(ops_unit, "Ops", "arithmetic(uint256,uint256)", (InternalCall,))
        assert len(ops) == 1
        assert ops[0].function is not None and ops[0].function.name == "_double"
        assert "INTERNAL_CALL function:_double" in str(ops[0])

    def test_lowlevel_call_in_factory(self, calls_unit):
        ops = _all_ops(calls_unit, (LowLevelCall,))
        assert ops

    def test_library_call_members_fixture(self):
        unit = _parse(FIXTURES / "parsing" / "Members.sol")
        ops = _all_ops(unit, (LibraryCall,))
        assert any(op.function_name == "validate" for op in ops)


# ------------------------------------------------------------- per-function
class TestPerFunctionCounters:
    def test_tmp_counters_restart_per_function(self, ops_unit):
        unit = ops_unit
        for f in unit.functions_and_modifiers:
            tmps = []
            for node in f.nodes:
                for op in node.ir_operations:
                    if isinstance(op.lvalue, TemporaryVariable):
                        tmps.append(op.lvalue.index)
            if tmps:
                assert min(tmps) == 0

    def test_ops_attached_to_nodes_with_backlinks(self, ops_unit):
        for f in ops_unit.functions_and_modifiers:
            for node in f.nodes:
                for op in node.ir_operations:
                    assert op.node is node
