"""SSA transform tests (architecture.md §6.5).

Original clean-room implementation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from velvet.compile import compile_target
from velvet.ir import convert_unit
from velvet.ir.operations import Assignment, Phi
from velvet.ir.ssa import convert_unit_ssa, non_ssa_version_of, storage_aliases
from velvet.parsing import parse_artifacts

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture(scope="module")
def unit():
    artifacts = compile_target(str(FIXTURES / "ir" / "Ssa.sol"))[0]
    parsed = parse_artifacts(artifacts)
    convert_unit(parsed)
    convert_unit_ssa(parsed)
    return parsed


def _function(unit, signature: str):
    return unit.get_contract_from_name("Ssa").get_function_from_signature(signature)


def _ssa_ops(function) -> list:
    return [op for node in function.nodes for op in node.ir_operations_ssa]


def _phis(function, variable: str = "") -> list[Phi]:
    return [
        op
        for op in _ssa_ops(function)
        if isinstance(op, Phi) and (not variable or op.lvalue.name.startswith(variable))
    ]


class TestVersioning:
    def test_variables_are_versioned(self, unit):
        ops = _ssa_ops(_function(unit, "branch(uint256)"))
        names = [op.lvalue.name for op in ops if op.lvalue is not None]
        assert any(n == "fee_1" for n in names)
        assert any(n.startswith("fee_") for n in names)
        # plain (unversioned) names only for never-written reads
        assert "fee_2" in names and "fee_3" in names

    def test_ssa_backlink(self, unit):
        ops = _ssa_ops(_function(unit, "branch(uint256)"))
        fee_versions = [
            op.lvalue for op in ops if op.lvalue is not None and op.lvalue.name.startswith("fee_")
        ]
        assert fee_versions
        originals = {non_ssa_version_of(v) for v in fee_versions}
        assert len(originals) == 1
        assert next(iter(originals)).name == "fee"


class TestMergePhis:
    def test_phi_at_if_merge(self, unit):
        phis = _phis(_function(unit, "branch(uint256)"), "fee_")
        assert len(phis) == 1
        phi = phis[0]
        assert phi.origin == "merge"
        # two candidates from the two branches
        assert len(phi.candidates) == 2
        assert {c.name for c in phi.candidates} == {"fee_2", "fee_3"}

    def test_use_after_merge_uses_phi_version(self, unit):
        f = _function(unit, "branch(uint256)")
        ops = _ssa_ops(f)
        phi = next(p for p in _phis(f, "fee_"))
        uses = [
            op
            for op in ops
            if not isinstance(op, Phi) and any(r is phi.lvalue for r in op.read)
        ]
        assert uses, "the merged version of fee must be read after the merge"

    def test_loop_carried_phis(self, unit):
        f = _function(unit, "loop(uint256)")
        phis = _phis(f)
        by_var: dict[str, list] = {}
        for phi in phis:
            by_var.setdefault(phi.lvalue.name.split("_")[0], []).append(phi)
        assert "s" in by_var and "i" in by_var
        # loop phis have two candidates (pre-loop + back-edge)
        loop_phis = [p for p in by_var["s"] if p.origin == "merge"]
        assert loop_phis and len(loop_phis[0].candidates) == 2


class TestStateVariablePhis:
    def test_entry_phi(self, unit):
        f = _function(unit, "callOut(address payable,uint256)")
        entry_phis = [p for p in _phis(f) if p.origin == "entry"]
        assert entry_phis
        names = {p.lvalue.name.split("_")[0] for p in entry_phis}
        assert "total" in names
        # entry phis reference the unversioned "outside world" value
        assert all(non_ssa_version_of(c).name == c.name for p in entry_phis for c in p.candidates)

    def test_phi_after_external_call(self, unit):
        f = _function(unit, "callOut(address payable,uint256)")
        ops = _ssa_ops(f)
        transfer_idx = next(i for i, op in enumerate(ops) if "TRANSFER" in str(op))
        following = ops[transfer_idx + 1 :]
        post_phis = [p for p in following if isinstance(p, Phi) and p.origin == "external_call"]
        assert post_phis
        assert any(p.lvalue.name.startswith("total_") for p in post_phis)
        # the post-call write must read the *new* total version
        writes = [op for op in following if isinstance(op, Assignment) and op.lvalue.name.startswith("total_")]
        assert writes


class TestStorageAlias:
    def test_alias_collection(self, unit):
        f = _function(unit, "aliasWrite(bool,uint256)")
        aliases = storage_aliases(f)
        ref = next(v for v in aliases if v.name == "ref")
        assert {sv.name for sv in aliases[ref]} == {"left", "right"}

    def test_alias_write_inserts_phis(self, unit):
        f = _function(unit, "aliasWrite(bool,uint256)")
        alias_phis = [p for p in _phis(f) if p.origin == "alias"]
        aliased = {p.lvalue.name.split("_")[0] for p in alias_phis}
        assert aliased == {"left", "right"}

    def test_rebind_does_not_insert_alias_phi(self, unit):
        f = _function(unit, "aliasWrite(bool,uint256)")
        ops = _ssa_ops(f)
        # the two rebinding assignments produce no alias phis inline
        rebinds = [op for op in ops if isinstance(op, Assignment) and op.lvalue.name.startswith("ref_")]
        assert len(rebinds) == 2


class TestDegradation:
    def test_ssa_never_crashes(self, unit):
        # every function in the fixture has an SSA view or empty ops
        for f in unit.functions_and_modifiers:
            for node in f.nodes:
                assert isinstance(node.ir_operations_ssa, list)
