"""Tests for reentrancy guard (mutex) recognition and suppression.

Covers the false-positive class introduced by modifier-body inlining in the
shared reentrancy core (src/velvet/detectors/_reentrancy_common.py):
functions guarded by an OpenZeppelin-style mutex modifier were flagged
because the guard variable (``_status``/``locked``) and the guarded state
appeared in the writes-after-call classification.

A state variable acts as a guard for an interaction when, on *every* path
of the modifier-spliced graph view, it is (a) checked by a guard condition
(``require``/``assert`` or if-revert) before the interaction, (b) written a
locked value inconsistent with the check before the interaction, and (c)
written an unlocked value after it.  Both boolean and uint-enum (1/2)
styles are recognized; guarded interactions have their findings suppressed
and guard-variable writes never count as findings.

Fixtures (fixtures/detectors/reentrancy-mutex/):

- ``oz_style.sol``    — uint-enum nonReentrant modifier (must not flag);
- ``bool_mutex.sol``  — boolean mutex variants (must not flag);
- ``broken_mutex.sol`` — check after the call / wrong lock value (MUST flag);
- ``partial_mutex.sol`` — guard on only one of two paths (MUST flag).

Original clean-room implementation.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from velvet.core.variables import Constant, StateVariable
from velvet.detectors._reentrancy_common import (
    _literal_int,
    _provably_different,
    _same_value,
    function_call_contexts,
    iter_analyzable_functions,
)
from velvet.detectors.base import Detector
from velvet.detectors.reentrancy_benign import ReentrancyBenign
from velvet.detectors.reentrancy_eth import ReentrancyEth
from velvet.detectors.reentrancy_events import ReentrancyEvents
from velvet.detectors.reentrancy_no_eth import ReentrancyNoEth
from velvet.session import Velvet

FIXTURES = (
    Path(__file__).resolve().parent.parent.parent
    / "fixtures"
    / "detectors"
    / "reentrancy-mutex"
)

ALL_REENTRANCY = (ReentrancyEth, ReentrancyNoEth, ReentrancyBenign, ReentrancyEvents)


def _run(detector_class: type[Detector], fixture: Path):
    session = Velvet(str(fixture))
    session.register_detector(detector_class)
    return [f for f in session.run_detectors() if f.check == detector_class.RULE]


def _descriptions(findings) -> list[str]:
    return [f.description for f in findings]


def _guards_by_function(fixture: Path) -> dict[str, list[str]]:
    """Map of canonical function name -> recognized guard variable names."""
    session = Velvet(str(fixture))
    session.register_detector(ReentrancyEth)
    session.run_detectors()
    unit = session.compilation_units[0]
    guards: dict[str, list[str]] = {}
    for function in iter_analyzable_functions(unit):
        for context in function_call_contexts(function):
            names = sorted(v.name for v in context.guarded_by)
            if names:
                guards.setdefault(function.canonical_name, []).extend(names)
    return guards


# --------------------------------------------------------------------------
# 1. OpenZeppelin-style uint-enum mutex (require and if-revert forms)
# --------------------------------------------------------------------------
class TestOzStyleMutex:
    @pytest.mark.parametrize("detector", ALL_REENTRANCY)
    def test_guarded_functions_not_flagged(self, detector):
        assert _run(detector, FIXTURES / "oz_style.sol") == []

    def test_status_recognized_as_guard(self):
        guards = _guards_by_function(FIXTURES / "oz_style.sol")
        assert guards["StatusGuardedVault.withdraw()"] == ["_status"]
        assert guards["StatusGuardedVault.notify(address)"] == ["_status"]
        # the if-revert form inverts the comparison (_status == ENTERED)
        assert guards["IfRevertGuardedVault.withdraw()"] == ["_status"]


# --------------------------------------------------------------------------
# 2. Boolean mutex variants (modifier, inline if-revert, guarded helper)
# --------------------------------------------------------------------------
class TestBoolMutex:
    @pytest.mark.parametrize("detector", ALL_REENTRANCY)
    def test_guarded_functions_not_flagged(self, detector):
        assert _run(detector, FIXTURES / "bool_mutex.sol") == []

    def test_locked_recognized_as_guard(self):
        guards = _guards_by_function(FIXTURES / "bool_mutex.sol")
        assert guards["BoolGuardedVault.withdraw()"] == ["locked"]
        assert guards["BoolGuardedVault.ping(address)"] == ["locked"]
        assert guards["CustomErrorGuardedVault.withdraw()"] == ["locked"]
        # the helper's call site is covered by the caller's modifier
        assert guards["HelperGuardedVault.withdraw()"] == ["locked"]

    def test_suppression_logs_debug(self, caplog):
        with caplog.at_level(logging.DEBUG, logger="velvet.detectors.reentrancy"):
            _run(ReentrancyEth, FIXTURES / "bool_mutex.sol")
        assert any(
            "behind reentrancy guard" in record.getMessage()
            for record in caplog.records
        )


# --------------------------------------------------------------------------
# 3. Broken mutexes (check after the call; wrong lock value) — MUST flag
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def eth_broken():
    return _run(ReentrancyEth, FIXTURES / "broken_mutex.sol")


class TestBrokenMutex:
    def test_late_check_still_flagged(self, eth_broken):
        descriptions = _descriptions(eth_broken)
        assert any("LateCheckVault.balances" in d for d in descriptions)
        assert any("LateCheckVault.withdraw()" in d for d in descriptions)

    def test_wrong_lock_value_still_flagged(self, eth_broken):
        descriptions = _descriptions(eth_broken)
        assert any("WrongValueVault.balances" in d for d in descriptions)
        # the mis-locked guard variable itself is not machinery here
        assert any("WrongValueVault._status" in d for d in descriptions)

    def test_exact_eth_count(self, eth_broken):
        assert len(eth_broken) == 3

    def test_late_check_mutex_var_flagged_benign(self):
        findings = _run(ReentrancyBenign, FIXTURES / "broken_mutex.sol")
        descriptions = _descriptions(findings)
        assert len(findings) == 1
        assert any("LateCheckVault.locked" in d for d in descriptions)

    def test_no_eth_and_events_silent(self):
        # both interactions move Ether; no events are emitted
        assert _run(ReentrancyNoEth, FIXTURES / "broken_mutex.sol") == []
        assert _run(ReentrancyEvents, FIXTURES / "broken_mutex.sol") == []


# --------------------------------------------------------------------------
# 4. Partial mutex (guard on only one of two paths) — MUST flag
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def eth_partial():
    return _run(ReentrancyEth, FIXTURES / "partial_mutex.sol")


class TestPartialMutex:
    def test_inline_partial_guard_flagged(self, eth_partial):
        descriptions = _descriptions(eth_partial)
        assert any("PartialInlineVault.balances" in d for d in descriptions)

    def test_modifier_partial_guard_flagged(self, eth_partial):
        descriptions = _descriptions(eth_partial)
        assert any("PartialModifierVault.balances" in d for d in descriptions)

    def test_exact_eth_count(self, eth_partial):
        # the balance write and the unprotected guard-variable write per
        # contract (a check that does not dominate is no guard at all)
        assert len(eth_partial) == 4

    def test_no_guard_recognized_on_partial_paths(self):
        guards = _guards_by_function(FIXTURES / "partial_mutex.sol")
        assert "PartialInlineVault.withdraw(bool)" not in guards
        assert "PartialModifierVault.withdraw(bool)" not in guards


# --------------------------------------------------------------------------
# 5. value-comparison helpers (no compilation needed)
# --------------------------------------------------------------------------
class TestValueHelpers:
    def test_literal_int_constant(self):
        assert _literal_int(Constant(2)) == 2
        assert _literal_int(Constant("0x10")) == 16
        assert _literal_int(Constant(True)) == 1
        assert _literal_int(Constant("true")) == 1
        assert _literal_int(Constant("false")) == 0
        assert _literal_int(Constant("not a number")) is None

    def test_literal_int_constant_state_variable(self):
        from velvet.core.expressions import Literal

        var = StateVariable()
        var.name = "ENTERED"
        var.is_constant = True
        assert _literal_int(var) is None  # no initializer
        var.expression_initial = Literal("2")
        assert _literal_int(var) == 2

    def test_same_value(self):
        assert _same_value(Constant(1), Constant("0x1"))
        assert not _same_value(Constant(1), Constant(2))
        var = StateVariable()
        var.name = "LOCKED"
        assert _same_value(var, var)
        assert not _same_value(var, Constant(1))

    def test_provably_different(self):
        assert _provably_different(Constant(1), Constant(2))
        assert _provably_different(Constant("true"), Constant(0))
        assert not _provably_different(Constant(2), Constant(2))
        # unknown values are never provably different (conservative)
        var = StateVariable()
        var.name = "X"
        assert not _provably_different(var, Constant(1))
