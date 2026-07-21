"""Tests for velvet.core model pieces built in Wave 1a."""

from __future__ import annotations

import pytest

from velvet.core.contract import Contract, c3_linearization
from velvet.core.expressions import (
    AssignmentOperation,
    BinaryOperation,
    ConditionalExpression,
    Identifier,
    Literal,
)
from velvet.core.function import Function, FunctionKind
from velvet.core.types import (
    ArrayType,
    ElementaryType,
    MappingType,
    TupleType,
)
from velvet.core.variables import (
    LocalVariable,
    StateVariable,
    solidity_function,
    solidity_variable,
)


# ------------------------------------------------------------------- C3
def test_c3_diamond():
    # D is B,C ; B is A ; C is A  =>  D, C, B, A
    # Solidity declares bases "most base-like first", so the linearization
    # (nearest first) lists the *last* declared base ahead of the earlier
    # ones (matches solc's linearizedBaseContracts for `contract D is B, C`).
    ancestors = {"A": [], "B": ["A"], "C": ["A"]}
    lino = c3_linearization("D", ["B", "C"], ancestors)
    assert lino == ["C", "B", "A"]


def test_c3_base_listed_before_its_parent():
    # OpenZeppelin pattern: `X is Initializable, ContextUpgradeable, I, E`
    # where ContextUpgradeable is Initializable and E is Initializable.
    # solc linearizes to [X, E, I, ContextUpgradeable, Initializable].
    ancestors = {"Init": [], "Ctx": ["Init"], "I": [], "E": ["Init"]}
    lino = c3_linearization("X", ["Init", "Ctx", "I", "E"], ancestors)
    assert lino == ["E", "I", "Ctx", "Init"]


def test_c3_linear_chain():
    ancestors = {"A": [], "B": ["A"]}
    assert c3_linearization("C", ["B"], ancestors) == ["B", "A"]


def test_c3_inconsistent_raises():
    # A is (C,D); B is (D,C); X is (A,B) => no consistent linearization
    ancestors = {"C": [], "D": [], "A": ["C", "D"], "B": ["D", "C"]}
    with pytest.raises(ValueError):
        c3_linearization("X", ["A", "B"], ancestors)


# ------------------------------------------------------------------ types
def test_elementary_type_alias_normalization():
    assert str(ElementaryType("uint")) == "uint256"
    assert str(ElementaryType("int")) == "int256"
    assert str(ElementaryType("byte")) == "bytes1"
    assert str(ElementaryType("address payable")) == "address payable"
    assert ElementaryType("uint128").size == 128


def test_composite_types_str():
    arr = ArrayType(ElementaryType("uint256"), None)
    assert str(arr) == "uint256[]"
    assert arr.is_dynamic
    fixed = ArrayType(ElementaryType("bool"), 3)
    assert str(fixed) == "bool[3]"
    mapping = MappingType(ElementaryType("address"), arr)
    assert str(mapping) == "mapping(address => uint256[])"
    tup = TupleType([ElementaryType("uint256"), ElementaryType("bool")])
    assert str(tup) == "tuple(uint256,bool)"


# -------------------------------------------------------------- variables
def test_solidity_builtins_singletons():
    assert solidity_variable("msg.sender") is solidity_variable("msg.sender")
    assert solidity_function("require") is solidity_function("require")
    assert solidity_variable("msg.sender").name == "msg.sender"


# ------------------------------------------------------------- expressions
def test_expression_str_and_walk():
    left = Identifier(_var("x"))
    right = Literal("1")
    assign = AssignmentOperation(left, BinaryOperation(Literal("2"), right, "+"), "+=")
    assert str(assign) == "x += 2 + 1"
    walked = list(assign.walk())
    assert len(walked) == 5  # assign, binop, ident, 2 literals... (+1 ident)
    assert not assign.contains_conditional


def test_conditional_detection():
    cond = ConditionalExpression(Literal("true"), Literal("1"), Literal("2"))
    assign = AssignmentOperation(Identifier(_var("x")), cond, "=")
    assert assign.contains_conditional


def _var(name: str) -> LocalVariable:
    v = LocalVariable()
    v.name = name
    return v


# -------------------------------------------------------------- functions
def test_function_signature_and_complexity():
    f = Function()
    f.name = "transfer"
    p = LocalVariable()
    p.name = "to"
    from velvet.core.types import ElementaryType as ET

    p.type = ET("address")
    f.parameters = [p]
    assert f.signature == "transfer(address)"
    assert f.cyclomatic_complexity == 1  # no nodes
    assert f.kind == FunctionKind.NORMAL
    f.set_kind(FunctionKind.RECEIVE)
    assert f.kind == FunctionKind.RECEIVE


# -------------------------------------------------------------- contracts
def test_contract_inheritance_views():
    base = Contract("Base")
    derived = Contract("Derived")
    derived.direct_bases = [base]
    derived.inheritance = [base]
    base.derived_contracts = [derived]

    var = StateVariable()
    var.name = "x"
    base.state_variables = [var]

    fn = Function()
    fn.name = "f"
    fn.visibility = "public"
    base.functions = [fn]

    assert derived.state_variables_ordered == [var]
    assert fn in derived.available_functions_from_inheritances()
    assert fn in derived.functions_entry_points


def test_contract_shadowing():
    base = Contract("Base")
    derived = Contract("Derived")
    derived.inheritance = [base]

    v1 = StateVariable()
    v1.name = "x"
    base.state_variables = [v1]
    v2 = StateVariable()
    v2.name = "x"
    derived.state_variables = [v2]

    assert derived.state_variables_shadowed == [v2]


def test_erc20_heuristic():
    c = Contract("T")
    for sig_name, params in [
        ("totalSupply", []),
        ("balanceOf", ["address"]),
        ("transfer", ["address", "uint256"]),
        ("transferFrom", ["address", "address", "uint256"]),
        ("approve", ["address", "uint256"]),
        ("allowance", ["address", "address"]),
    ]:
        fn = Function()
        fn.name = sig_name
        fn.visibility = "external"
        from velvet.core.types import ElementaryType as ET

        for i, ptype in enumerate(params):
            p = LocalVariable()
            p.name = f"p{i}"
            p.type = ET(ptype)
            fn.parameters.append(p)
        c.functions.append(fn)
    assert c.is_erc20()
