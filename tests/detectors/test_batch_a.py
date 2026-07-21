"""Golden tests for detector batch A (reentrancy + access control).

Each detector gets >=1 positive test (flags the vulnerable fixture) and >=1
negative test (clean on the safe fixture), run through the Velvet session
API (spec/detectors-catalog.md entries are normative).

Original clean-room implementation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from velvet.detectors._batch_a import DETECTORS
from velvet.detectors.arbitrary_send_eth import ArbitrarySendEth
from velvet.detectors.base import Confidence, Detector, DetectorDocs, Impact
from velvet.detectors.missing_zero_check import MissingZeroCheck
from velvet.detectors.protected_vars import ProtectedVars
from velvet.detectors.reentrancy_benign import ReentrancyBenign
from velvet.detectors.reentrancy_eth import ReentrancyEth
from velvet.detectors.reentrancy_events import ReentrancyEvents
from velvet.detectors.reentrancy_no_eth import ReentrancyNoEth
from velvet.detectors.suicidal import Suicidal
from velvet.detectors.unprotected_upgrade import UnprotectedUpgrade
from velvet.session import Velvet

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "detectors"

# Catalog-normative classification (spec/detectors-catalog.md).
EXPECTED_METADATA = {
    "reentrancy-eth": (Impact.HIGH, Confidence.MEDIUM),
    "reentrancy-no-eth": (Impact.MEDIUM, Confidence.MEDIUM),
    "reentrancy-benign": (Impact.LOW, Confidence.MEDIUM),
    "reentrancy-events": (Impact.LOW, Confidence.MEDIUM),
    "suicidal": (Impact.HIGH, Confidence.HIGH),
    "unprotected-upgrade": (Impact.HIGH, Confidence.HIGH),
    "arbitrary-send-eth": (Impact.HIGH, Confidence.MEDIUM),
    "missing-zero-check": (Impact.LOW, Confidence.MEDIUM),
    "protected-vars": (Impact.HIGH, Confidence.HIGH),
}


def _run(detector_class: type[Detector], fixture: Path):
    session = Velvet(str(fixture))
    session.register_detector(detector_class)
    return [
        f for f in session.run_detectors() if f.check == detector_class.RULE
    ]


class TestBatchMetadata:
    def test_batch_exports_nine_detectors(self):
        assert len(DETECTORS) == 9
        rules = [cls.RULE for cls in DETECTORS]
        assert len(set(rules)) == 9
        assert set(rules) == set(EXPECTED_METADATA)

    def test_metadata_matches_catalog(self):
        for cls in DETECTORS:
            impact, confidence = EXPECTED_METADATA[cls.RULE]
            assert cls.IMPACT is impact, cls.RULE
            assert cls.CONFIDENCE is confidence, cls.RULE
            assert cls.TITLE
            assert isinstance(cls.DOCS, DetectorDocs)
            assert cls.DOCS.url == (
                "https://github.com/velvet-analyzer/velvet/wiki/"
                f"Detector-Documentation#{cls.RULE}"
            )
            assert cls.DOCS.description
            assert cls.DOCS.exploit_scenario
            assert cls.DOCS.recommendation


# ------------------------------------------------------------------ fixtures
@pytest.fixture(scope="module")
def reentrancy_eth_vulnerable():
    return _run(ReentrancyEth, FIXTURES / "reentrancy-eth" / "vulnerable.sol")


@pytest.fixture(scope="module")
def reentrancy_eth_safe():
    return _run(ReentrancyEth, FIXTURES / "reentrancy-eth" / "safe.sol")


class TestReentrancyEth:
    def test_flags_classic_withdraw(self, reentrancy_eth_vulnerable):
        descriptions = [f.description for f in reentrancy_eth_vulnerable]
        assert len(reentrancy_eth_vulnerable) == 3
        assert any("EtherVault.balances" in d for d in descriptions)
        assert any("PrizePool.tickets" in d for d in descriptions)
        # both the read-before and the read-at-call metering patterns
        assert any("EtherVault.withdraw()" in d for d in descriptions)
        assert any("EtherVault.withdrawAll()" in d for d in descriptions)

    def test_send_transfer_only_not_flagged(self, reentrancy_eth_safe):
        assert reentrancy_eth_safe == []


@pytest.fixture(scope="module")
def reentrancy_no_eth_vulnerable():
    return _run(ReentrancyNoEth, FIXTURES / "reentrancy-no-eth" / "vulnerable.sol")


@pytest.fixture(scope="module")
def reentrancy_no_eth_safe():
    return _run(ReentrancyNoEth, FIXTURES / "reentrancy-no-eth" / "safe.sol")


class TestReentrancyNoEth:
    def test_flags_state_corruption(self, reentrancy_no_eth_vulnerable):
        descriptions = [f.description for f in reentrancy_no_eth_vulnerable]
        assert len(reentrancy_no_eth_vulnerable) == 2
        assert all("TokenAuction.settled" in d for d in descriptions)
        assert any("settleTyped" in d for d in descriptions)

    def test_checks_effects_interactions_clean(self, reentrancy_no_eth_safe):
        assert reentrancy_no_eth_safe == []


@pytest.fixture(scope="module")
def reentrancy_benign_vulnerable():
    return _run(ReentrancyBenign, FIXTURES / "reentrancy-benign" / "vulnerable.sol")


@pytest.fixture(scope="module")
def reentrancy_benign_safe():
    return _run(ReentrancyBenign, FIXTURES / "reentrancy-benign" / "safe.sol")


class TestReentrancyBenign:
    def test_flags_non_gating_writes(self, reentrancy_benign_vulnerable):
        descriptions = [f.description for f in reentrancy_benign_vulnerable]
        assert len(reentrancy_benign_vulnerable) == 3
        assert any("CallTracker.totalCalls" in d for d in descriptions)
        assert any("CallTracker.pings" in d for d in descriptions)

    def test_clean_when_write_precedes_call(self, reentrancy_benign_safe):
        assert reentrancy_benign_safe == []


@pytest.fixture(scope="module")
def reentrancy_events_vulnerable():
    return _run(ReentrancyEvents, FIXTURES / "reentrancy-events" / "vulnerable.sol")


@pytest.fixture(scope="module")
def reentrancy_events_safe():
    return _run(ReentrancyEvents, FIXTURES / "reentrancy-events" / "safe.sol")


class TestReentrancyEvents:
    def test_flags_event_after_interaction(self, reentrancy_events_vulnerable):
        descriptions = [f.description for f in reentrancy_events_vulnerable]
        assert len(reentrancy_events_vulnerable) == 2
        assert all("EpochCounter.epoch" in d for d in descriptions)
        assert any("advanceTwice" in d for d in descriptions)

    def test_event_before_call_clean(self, reentrancy_events_safe):
        assert reentrancy_events_safe == []


@pytest.fixture(scope="module")
def suicidal_vulnerable():
    return _run(Suicidal, FIXTURES / "suicidal" / "vulnerable.sol")


@pytest.fixture(scope="module")
def suicidal_safe():
    return _run(Suicidal, FIXTURES / "suicidal" / "safe.sol")


class TestSuicidal:
    def test_flags_unprotected_selfdestruct(self, suicidal_vulnerable):
        descriptions = [f.description for f in suicidal_vulnerable]
        assert len(suicidal_vulnerable) == 2
        assert any("resetMachine" in d for d in descriptions)
        assert any("shutdown" in d for d in descriptions)

    def test_owner_gated_clean(self, suicidal_safe):
        assert suicidal_safe == []


@pytest.fixture(scope="module")
def unprotected_upgrade_vulnerable():
    return _run(
        UnprotectedUpgrade, FIXTURES / "unprotected-upgrade" / "vulnerable.sol"
    )


@pytest.fixture(scope="module")
def unprotected_upgrade_safe():
    return _run(UnprotectedUpgrade, FIXTURES / "unprotected-upgrade" / "safe.sol")


class TestUnprotectedUpgrade:
    def test_flags_open_initializer(self, unprotected_upgrade_vulnerable):
        descriptions = [f.description for f in unprotected_upgrade_vulnerable]
        assert len(unprotected_upgrade_vulnerable) == 1
        assert "VaultLogicV1.initialize()" in descriptions[0]
        assert "no constructor disables initializers" in descriptions[0]

    def test_locked_implementation_clean(self, unprotected_upgrade_safe):
        assert unprotected_upgrade_safe == []


@pytest.fixture(scope="module")
def arbitrary_send_eth_vulnerable():
    return _run(
        ArbitrarySendEth, FIXTURES / "arbitrary-send-eth" / "vulnerable.sol"
    )


@pytest.fixture(scope="module")
def arbitrary_send_eth_safe():
    return _run(ArbitrarySendEth, FIXTURES / "arbitrary-send-eth" / "safe.sol")


class TestArbitrarySendEth:
    def test_flags_caller_chosen_destinations(self, arbitrary_send_eth_vulnerable):
        descriptions = [f.description for f in arbitrary_send_eth_vulnerable]
        assert len(arbitrary_send_eth_vulnerable) == 3
        assert any("drip(address payable,uint256)" in d for d in descriptions)
        assert any("dripTransfer" in d for d in descriptions)
        # destination through attacker-settable state
        assert any("dripStored" in d for d in descriptions)

    def test_authorized_and_fixed_recipients_clean(self, arbitrary_send_eth_safe):
        assert arbitrary_send_eth_safe == []


@pytest.fixture(scope="module")
def missing_zero_check_vulnerable():
    return _run(
        MissingZeroCheck, FIXTURES / "missing-zero-check" / "vulnerable.sol"
    )


@pytest.fixture(scope="module")
def missing_zero_check_safe():
    return _run(MissingZeroCheck, FIXTURES / "missing-zero-check" / "safe.sol")


class TestMissingZeroCheck:
    def test_flags_unchecked_address_storage(self, missing_zero_check_vulnerable):
        descriptions = [f.description for f in missing_zero_check_vulnerable]
        assert len(missing_zero_check_vulnerable) == 4
        assert any("TeamWallet.admin" in d for d in descriptions)
        assert any("TeamWallet.treasury" in d for d in descriptions)
        assert any("TeamWallet.pendingAdmin" in d for d in descriptions)
        assert any("constructor" in d for d in descriptions)

    def test_constructor_param_stored_unchecked_flagged(
        self, missing_zero_check_vulnerable
    ):
        constructor_findings = [
            f
            for f in missing_zero_check_vulnerable
            if "constructor" in f.description
        ]
        assert len(constructor_findings) == 1
        assert "foundation" in constructor_findings[0].description

    def test_validated_parameters_clean(self, missing_zero_check_safe):
        assert missing_zero_check_safe == []


@pytest.fixture(scope="module")
def protected_vars_vulnerable():
    return _run(ProtectedVars, FIXTURES / "protected-vars" / "vulnerable.sol")


@pytest.fixture(scope="module")
def protected_vars_safe():
    return _run(ProtectedVars, FIXTURES / "protected-vars" / "safe.sol")


class TestProtectedVars:
    def test_flags_writers_missing_documented_guard(self, protected_vars_vulnerable):
        descriptions = [f.description for f in protected_vars_vulnerable]
        assert len(protected_vars_vulnerable) == 2
        assert any("migrateTreasury" in d for d in descriptions)
        assert any("setFeeBps" in d for d in descriptions)
        assert all("onlyAdmin" in d for d in descriptions)

    def test_guarded_writers_clean(self, protected_vars_safe):
        assert protected_vars_safe == []
