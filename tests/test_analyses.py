"""Built-in analysis tests: read/write sets, protected, dependency, taint,
reachability (architecture.md §7).

Original clean-room implementation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from velvet.analyses import (
    entry_points_reaching,
    internal_calls_reachable,
    is_dependent,
    is_protected,
    is_reachable_from,
    is_tainted,
)
from velvet.compile import compile_target
from velvet.core.variables import StateVariable
from velvet.ir import convert_unit
from velvet.ir.ssa import convert_unit_ssa
from velvet.parsing import parse_artifacts

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _parse(name: str):
    artifacts = compile_target(str(FIXTURES / name))[0]
    unit = parse_artifacts(artifacts)
    convert_unit(unit)
    convert_unit_ssa(unit)
    return unit


@pytest.fixture(scope="module")
def multi():
    return _parse("analysis/Dependency.sol")


@pytest.fixture(scope="module")
def guarded():
    return _parse("analysis/Protected.sol")


@pytest.fixture(scope="module")
def token():
    return _parse("smoke/Token.sol")


@pytest.fixture(scope="module")
def ops():
    return _parse("ir/Ops.sol")


# --------------------------------------------------------------- read/write
class TestReadWrite:
    def test_node_sets(self, token):
        transfer = token.get_contract_from_name("Token").get_function_from_signature(
            "transfer(address,uint256)"
        )
        node_with_require = next(
            n for n in transfer.nodes if "require" in str(n.expression or "")
        )
        assert node_with_require.variables_read

    def test_function_sets(self, token):
        transfer = token.get_contract_from_name("Token").get_function_from_signature(
            "transfer(address,uint256)"
        )
        read = {v.name for v in transfer.state_variables_read}
        written = {v.name for v in transfer.state_variables_written}
        assert "balanceOf" in read
        assert "balanceOf" in written
        assert any(v.name == "amount" for v in transfer.variables_read)

    def test_write_through_ref_counts_as_state_write(self, token):
        transfer = token.get_contract_from_name("Token").get_function_from_signature(
            "transfer(address,uint256)"
        )
        written = transfer.state_variables_written
        assert any(isinstance(v, StateVariable) and v.name == "balanceOf" for v in written)

    def test_deep_variants_across_internal_calls(self, ops):
        contract = ops.get_contract_from_name("Ops")
        caller = next(f for f in contract.functions if f.internal_calls)
        own = {v.name for v in caller.state_variables_read}
        deep = {v.name for v in caller.state_variables_read_deep}
        assert deep >= own
        # the callee's reads flow into the caller's deep view
        callee = caller.internal_calls[0].function
        assert {v.name for v in callee.state_variables_read} <= deep

    def test_deep_terminates_on_recursion(self, token):
        # recursive-ish contracts would loop without a cycle guard
        for f in token.get_contract_from_name("Token").functions:
            f.state_variables_read_deep  # must not hang


# ---------------------------------------------------------------- protected
class TestProtected:
    def test_modifier_protected(self, guarded):
        f = guarded.get_contract_from_name("Guarded").get_function_from_signature(
            "setValue(uint256)"
        )
        assert is_protected(f) is True

    def test_inline_require_protected(self, guarded):
        f = guarded.get_contract_from_name("Guarded").get_function_from_signature(
            "setValueInline(uint256)"
        )
        assert is_protected(f) is True

    def test_if_condition_protected(self, guarded):
        f = guarded.get_contract_from_name("Guarded").get_function_from_signature(
            "setValueIf(uint256)"
        )
        assert is_protected(f) is True

    def test_unprotected(self, guarded):
        f = guarded.get_contract_from_name("Guarded").get_function_from_signature(
            "setValueOpen(uint256)"
        )
        assert is_protected(f) is False

    def test_constructor_is_protected(self, guarded):
        c = guarded.get_contract_from_name("Guarded")
        constructor = next(f for f in c.functions if f.is_constructor)
        assert is_protected(constructor) is True


# --------------------------------------------------------------- dependency
class TestDependency:
    def test_function_local(self, multi):
        contract = multi.get_contract_from_name("MultiTx")
        set_a = contract.get_function_from_signature("setA(uint256)")
        a = contract.get_state_variable_from_name("a")
        input_a = set_a.parameters[0]
        assert is_dependent(a, input_a, set_a) is True

    def test_function_local_negative(self, multi):
        contract = multi.get_contract_from_name("MultiTx")
        set_a = contract.get_function_from_signature("setA(uint256)")
        b = contract.get_state_variable_from_name("b")
        input_a = set_a.parameters[0]
        assert is_dependent(b, input_a, set_a) is False

    def test_contract_context_setA_setB(self, multi):
        """The wiki example: b depends on input_a across transactions."""
        contract = multi.get_contract_from_name("MultiTx")
        b = contract.get_state_variable_from_name("b")
        set_a = contract.get_function_from_signature("setA(uint256)")
        input_a = set_a.parameters[0]
        assert is_dependent(b, input_a, contract) is True

    def test_contract_context_independent_var(self, multi):
        contract = multi.get_contract_from_name("MultiTx")
        c = contract.get_state_variable_from_name("c")
        input_a = contract.get_function_from_signature("setA(uint256)").parameters[0]
        assert is_dependent(c, input_a, contract) is False

    def test_tainted_parameter(self, multi):
        contract = multi.get_contract_from_name("MultiTx")
        b = contract.get_state_variable_from_name("b")
        assert is_tainted(b, contract) is True

    def test_tainted_constructor_param(self, token):
        contract = token.get_contract_from_name("Token")
        name = contract.get_state_variable_from_name("name")
        assert is_tainted(name, contract) is True


# -------------------------------------------------------------- reachability
class TestReachability:
    def test_internal_calls_reachable(self, ops):
        contract = ops.get_contract_from_name("Ops")
        caller = next(f for f in contract.functions if f.internal_calls)
        targets = internal_calls_reachable(caller)
        assert targets
        assert any(t.name == "_double" for t in targets)

    def test_is_reachable_from(self, ops):
        contract = ops.get_contract_from_name("Ops")
        double = contract.get_function_from_signature("_double(uint256)")
        arithmetic = contract.get_function_from_signature("arithmetic(uint256,uint256)")
        assert is_reachable_from(arithmetic, double) is True
        assert is_reachable_from(double, arithmetic) is False

    def test_entry_points_reaching_this(self, ops):
        contract = ops.get_contract_from_name("Ops")
        double = contract.get_function_from_signature("_double(uint256)")
        entries = entry_points_reaching(double)
        assert entries
        assert all(e.visibility in ("external", "public") for e in entries)

    def test_library_call_targets_traversed(self):
        unit = _parse("detectors/dead-code/Library.sol")
        engine = unit.get_contract_from_name("Engine")
        run = engine.get_function_from_signature("run(uint256)")
        names = {t.name for t in internal_calls_reachable(run)}
        # the `using for` library call and its transitive internal helper
        assert "compute" in names
        assert "helper" in names

    def test_virtual_dispatch_reaches_overrides(self):
        unit = _parse("detectors/dead-code/Library.sol")
        base = unit.get_contract_from_name("BaseHook")
        engine = unit.get_contract_from_name("Engine")
        call_hook = base.get_function_from_signature("callHook()")
        names = {t.canonical_name for t in internal_calls_reachable(call_hook)}
        # the call dispatches through the base hook to its override
        assert "BaseHook.hook()" in names
        assert "Engine.hook()" in names

    def test_qualified_base_call_is_internal(self):
        unit = _parse("detectors/dead-code/Library.sol")
        engine = unit.get_contract_from_name("Engine")
        run_q = engine.get_function_from_signature("runQualified(uint256)")
        names = {t.name for t in internal_calls_reachable(run_q)}
        # `Engine.qualified(x)` is an internal statically-dispatched call
        assert "qualified" in names


# ----------------------------------------------------------- cfg conveniences
class TestCfgConveniences:
    def test_is_inside_loop(self, ops):
        loops_unit = _parse("cfg/Loops.sol")
        contract = next(iter(loops_unit.contracts_derived))
        function = next(
            f
            for f in contract.functions
            if any(n.kind.name == "IF_LOOP" for n in f.nodes)
        )
        inside = [n for n in function.nodes if n.is_inside_loop]
        assert inside, "expected some nodes inside the loop"
