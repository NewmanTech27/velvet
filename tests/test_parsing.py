"""Tests for velvet.parsing declaration/expression layers (Wave 1b)."""

from __future__ import annotations

from pathlib import Path

import pytest

from velvet.compile import compile_target
from velvet.compile.artifacts import CompilationArtifacts
from velvet.core.contract import ContractKind
from velvet.core.declarations import Structure
from velvet.core.expressions import (
    AssignmentOperation,
    CallExpression,
    Identifier,
    IndexAccess,
    TypeConversion,
)
from velvet.core.function import FunctionKind
from velvet.core.types import ArrayType, MappingType, UserDefinedType
from velvet.core.variables import (
    SolidityFunction,
    solidity_variable,
)
from velvet.parsing import parse_artifacts
from velvet.parsing.decl_parser import ParserContext
from velvet.parsing.type_parser import type_from_type_string

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _parse(path: Path):
    artifacts = compile_target(str(path))[0]
    return parse_artifacts(artifacts)


@pytest.fixture(scope="module")
def simple_unit():
    return _parse(FIXTURES / "smoke" / "Simple.sol")


@pytest.fixture(scope="module")
def token_unit():
    return _parse(FIXTURES / "smoke" / "Token.sol")


@pytest.fixture(scope="module")
def diamond_unit():
    return _parse(FIXTURES / "parsing" / "Diamond.sol")


@pytest.fixture(scope="module")
def members_unit():
    return _parse(FIXTURES / "parsing" / "Members.sol")


@pytest.fixture(scope="module")
def calls_unit():
    return _parse(FIXTURES / "parsing" / "Calls.sol")


# ------------------------------------------------------------- type strings
def test_type_string_elementary_and_alias():
    ctx = ParserContext(CompilationArtifacts())
    assert str(type_from_type_string("uint256", ctx)) == "uint256"
    assert str(type_from_type_string("address payable", ctx)) == "address payable"


def test_type_string_composites():
    ctx = ParserContext(CompilationArtifacts())
    mapping = type_from_type_string("mapping(address => uint256[])", ctx)
    assert isinstance(mapping, MappingType)
    assert str(mapping) == "mapping(address => uint256[])"
    nested = type_from_type_string("uint256[3][] memory", ctx)
    assert isinstance(nested, ArrayType)
    assert nested.is_dynamic
    assert isinstance(nested.type, ArrayType)
    assert nested.type.length == 3


def test_type_string_opaque_returns_none():
    ctx = ParserContext(CompilationArtifacts())
    assert type_from_type_string("int_const 5", ctx) is None
    assert type_from_type_string("msg", ctx) is None


# ---------------------------------------------------------------- contracts
@pytest.mark.integration
def test_contracts_found_with_kinds(simple_unit, diamond_unit, members_unit):
    simple = simple_unit.get_contract_from_name("Simple")
    assert simple is not None
    assert simple.kind == ContractKind.CONTRACT

    assert diamond_unit.get_contract_from_name("ICounter").kind == ContractKind.INTERFACE
    assert diamond_unit.get_contract_from_name("Base").kind == ContractKind.CONTRACT
    assert members_unit.get_contract_from_name("OrderBook").kind == ContractKind.LIBRARY
    assert [c.name for c in simple_unit.contracts] == ["Simple"]


@pytest.mark.integration
def test_state_variables(simple_unit, token_unit):
    simple = simple_unit.get_contract_from_name("Simple")
    value = simple.get_state_variable_from_name("value")
    owner = simple.get_state_variable_from_name("owner")
    assert str(value.type) == "uint256"
    assert value.visibility == "public"
    assert not value.is_constant
    assert str(owner.type) == "address"

    token = token_unit.get_contract_from_name("Token")
    balance_of = token.get_state_variable_from_name("balanceOf")
    assert isinstance(balance_of.type, MappingType)
    assert str(balance_of.type) == "mapping(address => uint256)"
    name = token.get_state_variable_from_name("name")
    assert str(name.type) == "string"


@pytest.mark.integration
def test_top_level_constant_and_function(members_unit):
    max_supply = members_unit.top_level_variables[0]
    assert max_supply.name == "MAX_SUPPLY"
    assert max_supply.is_constant
    assert max_supply.initialized
    assert str(max_supply.expression_initial) == "1000"

    assert [f.signature for f in members_unit.top_level_functions] == [
        "doubleIt(uint256)"
    ]
    # free functions get CFGs as well
    assert members_unit.top_level_functions[0].nodes


@pytest.mark.integration
def test_functions_signature_visibility_mutability(simple_unit, token_unit, diamond_unit):
    simple = simple_unit.get_contract_from_name("Simple")
    constructor = simple.functions[0]
    assert constructor.kind == FunctionKind.CONSTRUCTOR
    assert constructor.name == "constructor"
    assert constructor.signature == "constructor()"

    set_value = simple.get_function_from_signature("setValue(uint256)")
    assert set_value.visibility == "external"
    assert not (set_value.payable or set_value.view or set_value.pure)

    token = token_unit.get_contract_from_name("Token")
    transfer = token.get_function_from_signature("transfer(address,uint256)")
    assert transfer is not None
    assert len(transfer.returns) == 1
    assert str(transfer.returns[0].type) == "bool"

    version = diamond_unit.get_contract_from_name("Right").get_function_from_signature(
        "version()"
    )
    assert version.view
    assert version.virtual


@pytest.mark.integration
def test_parameters_types_and_locations(token_unit):
    token = token_unit.get_contract_from_name("Token")
    constructor = token.functions[0]
    assert len(constructor.parameters) == 1
    param = constructor.parameters[0]
    assert param.name == "n"
    assert str(param.type) == "string"
    assert param.location == "memory"

    transfer = token.functions[1]
    to, amount = transfer.parameters
    assert (to.name, str(to.type), to.location) == ("to", "address", None)
    assert (amount.name, str(amount.type)) == ("amount", "uint256")


@pytest.mark.integration
def test_pragmas(simple_unit):
    pragmas = simple_unit.pragmas
    assert len(pragmas) == 1
    assert pragmas[0].name == "solidity"
    assert pragmas[0].version == "^0.8.0"
    assert pragmas[0].directive == ["solidity", "^0.8.0"]


@pytest.mark.integration
def test_events_structs_enums_errors(members_unit):
    exchange = members_unit.get_contract_from_name("Exchange")
    event = exchange.events[0]
    assert event.name == "OrderPlaced"
    assert [p.name for p in event.elems] == ["maker", "amount", "status"]
    assert [p.indexed for p in event.elems] == [True, False, False]
    assert [str(p.type) for p in event.elems] == ["address", "uint256", "Status"]

    order = members_unit.structures[0]
    assert order.name == "Order"
    assert [(f.name, str(f.type)) for f in order.elems] == [
        ("maker", "address"),
        ("amount", "uint256"),
    ]

    status = members_unit.enums[0]
    assert status.name == "Status"
    assert status.values == ["Open", "Filled", "Cancelled"]

    error = members_unit.errors[0]
    assert error.name == "OrderTooLarge"
    assert error.signature == "OrderTooLarge(uint256,uint256)"


# -------------------------------------------------------------- inheritance
@pytest.mark.integration
def test_c3_linearization_diamond(diamond_unit):
    diamond = diamond_unit.get_contract_from_name("Diamond")
    assert [b.name for b in diamond.direct_bases] == ["Left", "Right"]
    # Solidity declares bases most-base-like first, so the linearization
    # (nearest first) lists the last declared base ahead of the earlier one;
    # matches solc's linearizedBaseContracts for `contract Diamond is Left, Right`.
    assert [b.name for b in diamond.inheritance] == ["Right", "Left", "Base", "ICounter"]
    assert [b.name for b in diamond.inheritance_reverse] == [
        "ICounter",
        "Base",
        "Left",
        "Right",
    ]


@pytest.mark.integration
def test_derived_contracts(diamond_unit):
    base = diamond_unit.get_contract_from_name("Base")
    assert sorted(c.name for c in base.derived_contracts) == ["Left", "Right"]
    assert [c.name for c in diamond_unit.contracts_derived] == ["Diamond"]


@pytest.mark.integration
def test_override_graph(diamond_unit):
    base = diamond_unit.get_contract_from_name("Base")
    left = diamond_unit.get_contract_from_name("Left")
    base_bump = base.get_function_from_signature("bump()")
    left_bump = left.get_function_from_signature("bump()")
    assert left_bump.overrides == [base_bump]
    assert left_bump in base_bump.overridden_by


# --------------------------------------------------------- symbol resolution
@pytest.mark.integration
def test_identifier_resolution(token_unit):
    token = token_unit.get_contract_from_name("Token")
    transfer = token.get_function_from_signature("transfer(address,uint256)")

    require_call = transfer.nodes[1].expression
    assert isinstance(require_call, CallExpression)
    assert isinstance(require_call.called, Identifier)
    assert require_call.called.value == SolidityFunction("require")

    decrease = transfer.nodes[2].expression
    assert isinstance(decrease, AssignmentOperation)
    assert decrease.operator == "-="
    lhs = decrease.expression_left
    assert isinstance(lhs, IndexAccess)
    balance_of = token.get_state_variable_from_name("balanceOf")
    assert lhs.expression_left.value is balance_of
    index = lhs.expression_right
    assert isinstance(index, Identifier)
    assert index.value is solidity_variable("msg.sender")


@pytest.mark.integration
def test_msg_sender_member_access(simple_unit):
    simple = simple_unit.get_contract_from_name("Simple")
    constructor = simple.functions[0]
    assign = constructor.nodes[1].expression
    rhs = assign.expression_right
    assert isinstance(rhs, Identifier)
    assert rhs.value is solidity_variable("msg.sender")


@pytest.mark.integration
def test_constant_identifier_resolution(members_unit):
    book = members_unit.get_contract_from_name("OrderBook")
    validate = book.functions[0]
    # `if (o.amount > MAX_SUPPLY)` — the constant identifier must resolve to
    # the top-level constant StateVariable.
    if_node = validate.nodes[1]
    condition = if_node.expression
    right = condition.expression_right
    assert isinstance(right, Identifier)
    assert right.value is members_unit.top_level_variables[0]


@pytest.mark.integration
def test_using_for_resolution(members_unit):
    exchange = members_unit.get_contract_from_name("Exchange")
    directive = exchange.using_for[0]
    assert directive.library_name == "OrderBook"
    assert directive.library is members_unit.get_contract_from_name("OrderBook")
    assert isinstance(directive.type, UserDefinedType)
    assert isinstance(directive.type.type, Structure)
    assert directive.type.type.name == "Order"


@pytest.mark.integration
def test_user_defined_types_resolved(members_unit):
    exchange = members_unit.get_contract_from_name("Exchange")
    orders = exchange.get_state_variable_from_name("orders")
    assert isinstance(orders.type, ArrayType)
    element = orders.type.type
    assert isinstance(element, UserDefinedType)
    assert element.type is members_unit.structures[0]

    place = exchange.get_function_from_signature("place(uint256)")
    declaration_node = place.nodes[1]
    local = declaration_node.variable_declaration
    assert local.name == "o"
    assert isinstance(local.type, UserDefinedType)
    assert local.type.type is members_unit.structures[0]
    assert local.location == "memory"


@pytest.mark.integration
def test_call_options_attached(calls_unit):
    factory = calls_unit.get_contract_from_name("Factory")

    spawn = factory.get_function_from_signature("spawn()")
    new_call = spawn.nodes[1].expression.expression_right
    assert isinstance(new_call, CallExpression)
    assert str(new_call.call_value) == "1"
    assert new_call.call_gas is None

    forward = factory.get_function_from_signature("forward(address payable)")
    low_call = forward.nodes[1].expression.expression_right
    assert isinstance(low_call, CallExpression)
    assert str(low_call.call_value) == "msg.value"
    assert str(low_call.call_gas) == "3000"


@pytest.mark.integration
def test_type_conversion_parsed(calls_unit):
    factory = calls_unit.get_contract_from_name("Factory")
    widen = factory.get_function_from_signature("widen(uint64)")
    conversion = widen.nodes[1].expression
    assert isinstance(conversion, TypeConversion)
    assert str(conversion.type) == "uint256"
    assert str(conversion.expression) == "small"


@pytest.mark.integration
def test_source_mappings_sane(simple_unit):
    simple = simple_unit.get_contract_from_name("Simple")
    assert simple.source_mapping.lines
    value = simple.get_state_variable_from_name("value")
    assert value.source_mapping.lines
    assert "uint256" in value.source_mapping.content
    constructor = simple.functions[0]
    assert constructor.source_mapping.lines[0] >= 1
    assert "constructor" in constructor.source_mapping.content
