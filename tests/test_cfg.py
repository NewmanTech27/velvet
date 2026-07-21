"""Tests for CFG construction (Wave 1b, spec/architecture.md §5)."""

from __future__ import annotations

from pathlib import Path

import pytest

from velvet.compile import compile_target
from velvet.core.cfg_node import NodeKind
from velvet.core.expressions import ConditionalExpression
from velvet.core.function import FunctionLike
from velvet.parsing import parse_artifacts

FIXTURES = Path(__file__).parent.parent / "fixtures" / "cfg"

STRUCTURAL_WITHOUT_EXPRESSION = {
    NodeKind.ENTRYPOINT,
    NodeKind.ENDIF,
    NodeKind.START_LOOP,
    NodeKind.END_LOOP,
    NodeKind.BREAK,
    NodeKind.CONTINUE,
    NodeKind.CATCH,
    NodeKind.ASSEMBLY,
}


def _parse(name: str):
    artifacts = compile_target(str(FIXTURES / name))[0]
    return parse_artifacts(artifacts)


@pytest.fixture(scope="module")
def branching_unit():
    return _parse("Branching.sol")


@pytest.fixture(scope="module")
def loops_unit():
    return _parse("Loops.sol")


@pytest.fixture(scope="module")
def ternary_unit():
    return _parse("Ternary.sol")


@pytest.fixture(scope="module")
def modifiers_unit():
    return _parse("Modifiers.sol")


@pytest.fixture(scope="module")
def assembly_try_unit():
    return _parse("AssemblyTry.sol")


def _kinds(function: FunctionLike) -> list[NodeKind]:
    return [n.kind for n in function.nodes]


def _fn(unit, contract: str, signature: str):
    return unit.get_contract_from_name(contract).get_function_from_signature(signature)


# ------------------------------------------------------------------ if/else
@pytest.mark.integration
def test_if_else_join_and_endif(branching_unit):
    classify = _fn(branching_unit, "Branching", "classify(int256)")
    assert _kinds(classify) == [
        NodeKind.ENTRYPOINT,
        NodeKind.VARIABLE,
        NodeKind.IF,
        NodeKind.EXPRESSION,
        NodeKind.IF,
        NodeKind.EXPRESSION,
        NodeKind.EXPRESSION,
        NodeKind.ENDIF,
        NodeKind.ENDIF,
        NodeKind.RETURN,
    ]
    first_if = classify.nodes[2]
    assert str(first_if.expression) == "x < 0"
    assert len(first_if.successors) == 2  # condition node branches both ways
    inner_endif = classify.nodes[7]
    assert len(inner_endif.predecessors) == 2  # join of then/else
    outer_endif = classify.nodes[8]
    assert outer_endif.successors == [classify.nodes[9]]


@pytest.mark.integration
def test_endif_pruned_when_both_branches_return(branching_unit):
    sign = _fn(branching_unit, "Branching", "sign(int256)")
    assert _kinds(sign) == [
        NodeKind.ENTRYPOINT,
        NodeKind.IF,
        NodeKind.RETURN,
        NodeKind.RETURN,
    ]
    assert all(n.kind != NodeKind.ENDIF for n in sign.nodes)


@pytest.mark.integration
def test_if_without_else_joins(branching_unit):
    touch = _fn(branching_unit, "Branching", "touch(uint256)")
    assert _kinds(touch) == [
        NodeKind.ENTRYPOINT,
        NodeKind.IF,
        NodeKind.EXPRESSION,
        NodeKind.ENDIF,
        NodeKind.RETURN,
    ]
    endif = touch.nodes[3]
    # joined by the body and by the (false edge of the) condition
    assert set(endif.predecessors) == {touch.nodes[1], touch.nodes[2]}


# -------------------------------------------------------------------- loops
@pytest.mark.integration
def test_for_loop_structure(loops_unit):
    sum_first = _fn(loops_unit, "Loops", "sumFirst(uint256)")
    assert _kinds(sum_first) == [
        NodeKind.ENTRYPOINT,
        NodeKind.VARIABLE,  # for-init lands before the loop
        NodeKind.START_LOOP,
        NodeKind.IF_LOOP,
        NodeKind.IF,
        NodeKind.BREAK,
        NodeKind.ENDIF,
        NodeKind.EXPRESSION,  # body
        NodeKind.EXPRESSION,  # post (i++)
        NodeKind.END_LOOP,
        NodeKind.RETURN,  # synthesized trailing return of named `total`
    ]
    entry = sum_first.nodes[0]
    assert sum_first.entry_point is entry
    init = sum_first.nodes[1]
    assert init.variable_declaration.name == "i"
    if_loop = sum_first.nodes[3]
    assert len(if_loop.successors) == 2
    post = sum_first.nodes[8]
    assert post.successors == [if_loop]  # back edge via the post expression
    end_loop = sum_first.nodes[9]
    assert end_loop in if_loop.successors  # false edge exits the loop


@pytest.mark.integration
def test_break_repoints_after_loop(loops_unit):
    sum_first = _fn(loops_unit, "Loops", "sumFirst(uint256)")
    break_node = next(n for n in sum_first.nodes if n.kind == NodeKind.BREAK)
    end_loop = next(n for n in sum_first.nodes if n.kind == NodeKind.END_LOOP)
    after_loop = sum_first.nodes[end_loop.node_id + 1]
    assert break_node.successors == [after_loop]


@pytest.mark.integration
def test_while_continue_repoints_to_condition(loops_unit):
    countdown = _fn(loops_unit, "Loops", "countdown(uint256)")
    kinds = _kinds(countdown)
    assert NodeKind.START_LOOP in kinds and NodeKind.IF_LOOP in kinds
    if_loop = next(n for n in countdown.nodes if n.kind == NodeKind.IF_LOOP)
    assert str(if_loop.expression) == "remaining > 0"
    continue_node = next(n for n in countdown.nodes if n.kind == NodeKind.CONTINUE)
    assert continue_node.successors == [if_loop]
    # body tail flows back into the condition
    assert if_loop in countdown.nodes[9].successors


@pytest.mark.integration
def test_do_while_runs_body_first(loops_unit):
    halve = _fn(loops_unit, "Loops", "halve(uint256)")
    assert _kinds(halve) == [
        NodeKind.ENTRYPOINT,
        NodeKind.IF,
        NodeKind.RETURN,
        NodeKind.ENDIF,
        NodeKind.START_LOOP,
        NodeKind.EXPRESSION,
        NodeKind.EXPRESSION,
        NodeKind.IF_LOOP,
        NodeKind.END_LOOP,
        NodeKind.RETURN,
    ]
    if_loop = halve.nodes[7]
    body_top = halve.nodes[5]
    assert body_top in if_loop.successors  # true edge repeats the body
    assert halve.nodes[8] in if_loop.successors  # false edge exits


# ------------------------------------------------------------------ ternary
@pytest.mark.integration
def test_ternary_is_lowered(ternary_unit):
    max_fn = _fn(ternary_unit, "Ternary", "max(uint256,uint256)")
    assert _kinds(max_fn) == [
        NodeKind.ENTRYPOINT,
        NodeKind.IF,
        NodeKind.EXPRESSION,
        NodeKind.EXPRESSION,
        NodeKind.ENDIF,
        NodeKind.VARIABLE,
        NodeKind.RETURN,
    ]
    # no control flow survives inside any expression
    for node in max_fn.nodes:
        if node.expression is not None:
            assert not node.expression.contains_conditional
    assert len(max_fn.synthesized_locals) == 1
    temp = max_fn.synthesized_locals[0]
    assert temp.location == "memory"
    assert str(temp.type) == "uint256"
    declaration = max_fn.nodes[5]
    assert declaration.variable_declaration.name == "best"


@pytest.mark.integration
def test_nested_ternary_lowers_innermost_first(ternary_unit):
    floor = _fn(ternary_unit, "Ternary", "floor(int256)")
    assert len(floor.synthesized_locals) == 2
    ifs = [n for n in floor.nodes if n.kind == NodeKind.IF]
    assert len(ifs) == 2
    # the inner condition (x < -100) is lowered before the outer one (x < 0)
    assert str(ifs[0].expression) == "x < -100"
    assert str(ifs[1].expression) == "x < 0"
    for node in floor.nodes:
        if node.expression is not None:
            assert not isinstance(node.expression, ConditionalExpression)


# ----------------------------------------------------------------- modifiers
@pytest.mark.integration
def test_modifiers_have_cfgs_and_apply_in_order(modifiers_unit):
    guarded = modifiers_unit.get_contract_from_name("Guarded")
    sensitive = guarded.get_function_from_signature("sensitive(uint256)")
    assert [m.name for m in sensitive.modifiers] == ["onlyOwner", "whenUnlocked"]

    only_owner = guarded.modifiers[0]
    assert _kinds(only_owner) == [
        NodeKind.ENTRYPOINT,
        NodeKind.EXPRESSION,
        NodeKind.PLACEHOLDER,  # the `_` splice point
        NodeKind.RETURN,
    ]
    when_unlocked = guarded.modifiers[1]
    assert _kinds(when_unlocked) == [
        NodeKind.ENTRYPOINT,
        NodeKind.IF,
        NodeKind.EXPRESSION,  # revert("locked") is a builtin call expression
        NodeKind.ENDIF,
        NodeKind.PLACEHOLDER,
        NodeKind.RETURN,
    ]


# ----------------------------------------------------------- assembly / try
@pytest.mark.integration
def test_inline_assembly_is_one_opaque_node(assembly_try_unit):
    manual_add = _fn(assembly_try_unit, "AssemblyTry", "manualAdd(uint256,uint256)")
    assert manual_add.contains_assembly
    assert _kinds(manual_add) == [
        NodeKind.ENTRYPOINT,
        NodeKind.ASSEMBLY,
        NodeKind.RETURN,
    ]
    assembly_node = manual_add.nodes[1]
    assert assembly_node.expression is None
    # named return gets a synthesized trailing RETURN
    trailing = manual_add.nodes[2]
    assert str(trailing.expression) == "result"


@pytest.mark.integration
def test_try_catch_structure(assembly_try_unit):
    fetch = _fn(assembly_try_unit, "AssemblyTry", "fetch()")
    assert _kinds(fetch) == [
        NodeKind.ENTRYPOINT,
        NodeKind.TRY,
        NodeKind.EXPRESSION,
        NodeKind.EXPRESSION,
        NodeKind.CATCH,
        NodeKind.THROW,
        NodeKind.RETURN,
    ]
    try_node = fetch.nodes[1]
    assert len(try_node.successors) == 2  # success path + catch clause
    catch = fetch.nodes[4]
    assert catch in try_node.successors
    throw = fetch.nodes[5]
    assert throw.successors == []
    # the success branch joins the synthesized named-return RETURN
    emit_node = fetch.nodes[3]
    trailing = fetch.nodes[6]
    assert emit_node.successors == [trailing]
    assert str(trailing.expression) == "value"


@pytest.mark.integration
def test_unimplemented_function_has_no_nodes(assembly_try_unit):
    get = assembly_try_unit.get_contract_from_name("IOracle").functions[0]
    assert not get.is_implemented
    assert get.nodes == []
    assert get.entry_point is None


# ---------------------------------------------------------------- invariants
@pytest.mark.integration
def test_all_paths_end_in_return_or_throw(branching_unit, loops_unit, ternary_unit):
    for unit in (branching_unit, loops_unit, ternary_unit):
        for contract in unit.contracts:
            for function in contract.functions_and_modifiers:
                for node in function.nodes:
                    if not node.successors:
                        assert node.kind in (NodeKind.RETURN, NodeKind.THROW), (
                            f"{function.canonical_name} node #{node.node_id} "
                            f"({node.kind.name}) is a dead end"
                        )


@pytest.mark.integration
def test_one_expression_per_node_and_structural_nodes_empty(
    branching_unit, loops_unit, assembly_try_unit
):
    for unit in (branching_unit, loops_unit, assembly_try_unit):
        for contract in unit.contracts:
            for function in contract.functions_and_modifiers:
                for node in function.nodes:
                    if node.kind in STRUCTURAL_WITHOUT_EXPRESSION:
                        assert node.expression is None
                    else:
                        assert node.expression is None or not isinstance(
                            node.expression, list
                        )


@pytest.mark.integration
def test_unreachable_nodes_marked_not_deleted(branching_unit):
    dead = _fn(branching_unit, "Branching", "deadAfterBothReturn(int256)")
    kinds = _kinds(dead)
    assert NodeKind.ENDIF not in kinds  # pruned: both branches return
    trailing = dead.nodes[-1]
    assert trailing.kind == NodeKind.RETURN
    assert not trailing.is_reachable
    assert trailing.predecessors == []
    reachable = [n for n in dead.nodes if n.is_reachable]
    assert reachable == dead.nodes[:-1]


@pytest.mark.integration
def test_node_source_mappings_have_sane_lines(loops_unit):
    for contract in loops_unit.contracts:
        for function in contract.functions_and_modifiers:
            for node in function.nodes:
                lines = node.source_mapping.lines
                assert lines, f"{function.canonical_name}#{node.node_id} has no lines"
                assert lines[0] >= 1
                assert node.source_mapping.filename is not None


@pytest.mark.integration
def test_node_ids_contiguous_and_unique(loops_unit):
    for contract in loops_unit.contracts:
        for function in contract.functions_and_modifiers:
            ids = [n.node_id for n in function.nodes]
            assert ids == list(range(len(ids)))
