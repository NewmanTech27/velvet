"""Batch C detector tests (spec/detectors-catalog.md — normative entries).

Each detector has at least one positive (vulnerable pattern flagged) and
one negative (safe pattern / unaffected compiler not flagged) test.

Original clean-room implementation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from velvet.detectors._batch_c import DETECTORS
from velvet.detectors.base import Confidence, DetectorDocs, Impact
from velvet.session import Velvet

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "detectors"


def _session(path: Path) -> Velvet:
    session = Velvet(str(path))
    for cls in DETECTORS:
        session.register_detector(cls)
    return session


def _findings(session: Velvet, rule: str):
    return [f for f in session.run_detectors() if f.check == rule]


# ---------------------------------------------------------------- metadata
class TestBatchCMetadata:
    def test_rules_unique_and_kebab_case(self):
        rules = [cls.RULE for cls in DETECTORS]
        assert len(rules) == len(set(rules))
        for rule in rules:
            assert rule == rule.lower() and " " not in rule and "_" not in rule

    def test_metadata_complete(self):
        expected = {
            "unused-state",
            "shadowing-state",
            "shadowing-builtin",
            "naming-convention",
            "abiencoderv2-array",
            "storage-array",
            "assembly",
            "low-level-calls",
            "constable-states",
            "immutable-states",
        }
        assert {cls.RULE for cls in DETECTORS} == expected
        for cls in DETECTORS:
            assert cls.TITLE
            assert isinstance(cls.IMPACT, Impact)
            assert isinstance(cls.CONFIDENCE, Confidence)
            assert isinstance(cls.DOCS, DetectorDocs)
            assert cls.DOCS.url.startswith("http")
            assert cls.DOCS.description
            assert cls.DOCS.exploit_scenario
            assert cls.DOCS.recommendation


# ------------------------------------------------------------- unused-state
@pytest.fixture(scope="module")
def unused_state_session():
    return _session(FIXTURES / "unused-state" / "UnusedState.sol")


class TestUnusedState:
    RULE = "unused-state"

    def test_positive_never_read_variables_flagged(self, unused_state_session):
        findings = _findings(unused_state_session, self.RULE)
        assert findings
        assert any("legacySupply" in f.description for f in findings)
        # written in the constructor but never read
        assert any("admin" in f.description for f in findings)
        assert all(f.impact == Impact.INFORMATIONAL for f in findings)

    def test_negative_read_and_public_variables_not_flagged(
        self, unused_state_session
    ):
        findings = _findings(unused_state_session, self.RULE)
        # public variable: implicit getter counts as a reader
        assert not any("name" in f.description for f in findings)
        # private variables read by functions (incl. via internal helpers)
        assert not any("total" in f.description for f in findings)
        assert not any("UsedStateToken.admin" in f.description for f in findings)


# ---------------------------------------------------------- shadowing-state
@pytest.fixture(scope="module")
def shadowing_state_session():
    return _session(FIXTURES / "shadowing-state" / "ShadowingState.sol")


class TestShadowingState:
    RULE = "shadowing-state"

    def test_positive_redeclared_owner_flagged(self, shadowing_state_session):
        findings = _findings(shadowing_state_session, self.RULE)
        assert len(findings) == 1
        assert "owner" in findings[0].description
        assert "Owned" in findings[0].description
        assert findings[0].impact == Impact.HIGH

    def test_negative_inherited_assignment_not_flagged(self, shadowing_state_session):
        findings = _findings(shadowing_state_session, self.RULE)
        assert not any("CleanVault" in f.description for f in findings)
        assert not any("OwnedSafe" in f.description for f in findings)


# -------------------------------------------------------- shadowing-builtin
@pytest.fixture(scope="module")
def shadowing_builtin_session():
    return _session(FIXTURES / "shadowing-builtin" / "ShadowingBuiltin.sol")


class TestShadowingBuiltin:
    RULE = "shadowing-builtin"

    def test_positive_builtin_names_flagged(self, shadowing_builtin_session):
        findings = _findings(shadowing_builtin_session, self.RULE)
        names = {f.additional_fields.get("builtin") for f in findings}
        assert {"now", "sha3", "suicide"} <= names
        assert all(f.impact == Impact.LOW for f in findings)

    def test_negative_plain_names_not_flagged(self, shadowing_builtin_session):
        findings = _findings(shadowing_builtin_session, self.RULE)
        assert not any("CleanClock" in f.description for f in findings)


# -------------------------------------------------------- naming-convention
@pytest.fixture(scope="module")
def naming_session():
    return _session(FIXTURES / "naming-convention" / "NamingConvention.sol")


class TestNamingConvention:
    RULE = "naming-convention"

    def test_positive_style_violations_flagged(self, naming_session):
        findings = _findings(naming_session, self.RULE)
        descriptions = [f.description for f in findings]
        assert any("my_token" in d and "CapWords" in d for d in descriptions)
        assert any("TOTAL" in d and "mixedCase" in d for d in descriptions)
        assert any(
            "maxSupply" in d and "UPPER_CASE_WITH_UNDERSCORES" in d
            for d in descriptions
        )
        assert any("TransferCoins" in d and "mixedCase" in d for d in descriptions)
        assert any("transferred" in d and "CapWords" in d for d in descriptions)
        assert any("BAD_local" in d and "mixedCase" in d for d in descriptions)
        assert any("OnlyAdmin" in d and "mixedCase" in d for d in descriptions)
        assert all(
            f.additional_fields.get("convention")
            in {"CapWords", "mixedCase", "UPPER_CASE_WITH_UNDERSCORES"}
            for f in findings
        )

    def test_negative_compliant_names_not_flagged(self, naming_session):
        findings = _findings(naming_session, self.RULE)
        descriptions = [f.description for f in findings]
        assert not any("MyToken" in d for d in descriptions)
        assert not any("MAX_SUPPLY" in d for d in descriptions)
        # documented ERC-20 lowercase exception
        assert not any("MyToken.name" in d for d in descriptions)


@pytest.fixture(scope="module")
def conventions_session():
    return _session(FIXTURES / "naming-convention" / "Conventions.sol")


class TestNamingConventionExceptions:
    RULE = "naming-convention"

    def test_used_leading_underscore_parameter_flagged(self, conventions_session):
        findings = _findings(conventions_session, self.RULE)
        flagged = [f.description for f in findings]
        assert any("_amount" in d and "pay(" in d for d in flagged)
        assert any("_bumpPublic" in d for d in flagged)
        assert any("__doubleCounter" in d for d in flagged)

    def test_same_name_parameters_are_distinct_findings(self, conventions_session):
        findings = _findings(conventions_session, self.RULE)
        bad = [f for f in findings if "Bad_Param" in f.description]
        assert len(bad) == 2

    def test_documented_exceptions_not_flagged(self, conventions_session):
        findings = _findings(conventions_session, self.RULE)
        flagged = " ".join(f.description for f in findings)
        # private variable / internal function with one leading underscore
        assert "_privateCounter (" not in flagged
        assert "_bumpInternal" not in flagged
        # unused parameter may keep its leading underscore
        assert "payUnused" not in flagged
        # trailing underscore disambiguation from state variables
        assert "amount_" not in flagged
        assert "counter_" not in flagged
        # "$" carries no case (ERC-7201 storage-pointer idiom)
        assert "$" not in flagged


# ------------------------------------------------------- abiencoderv2-array
@pytest.fixture(scope="module")
def abiencoderv2_session():
    return _session(FIXTURES / "abiencoderv2-array" / "AbiEncoderV2Array.sol")


@pytest.fixture(scope="module")
def abiencoderv2_fixed_session():
    return _session(FIXTURES / "abiencoderv2-array" / "AbiEncoderV2ArrayFixed.sol")


class TestAbiEncoderV2Array:
    RULE = "abiencoderv2-array"

    def test_positive_nested_array_encode_flagged(self, abiencoderv2_session):
        findings = _findings(abiencoderv2_session, self.RULE)
        assert len(findings) == 1
        assert "abi.encode" in findings[0].description
        assert findings[0].impact == Impact.HIGH

    def test_negative_flat_array_not_flagged(self, abiencoderv2_session):
        findings = _findings(abiencoderv2_session, self.RULE)
        assert not any("FlatEncoder" in f.description for f in findings)

    def test_negative_fixed_compiler_not_flagged(self, abiencoderv2_fixed_session):
        assert _findings(abiencoderv2_fixed_session, self.RULE) == []


# ------------------------------------------------------------- storage-array
@pytest.fixture(scope="module")
def storage_array_session():
    return _session(FIXTURES / "storage-array" / "StorageArray.sol")


@pytest.fixture(scope="module")
def storage_array_fixed_session():
    return _session(FIXTURES / "storage-array" / "StorageArrayFixed.sol")


class TestStorageArray:
    RULE = "storage-array"

    def test_positive_negative_literal_assignments_flagged(self, storage_array_session):
        findings = _findings(storage_array_session, self.RULE)
        # whole-array literal assignment and element-level assignment
        assert len(findings) == 2
        assert all("values" in f.description for f in findings)
        assert findings[0].impact == Impact.HIGH

    def test_negative_positive_and_unsigned_not_flagged(self, storage_array_session):
        findings = _findings(storage_array_session, self.RULE)
        assert not any("PositiveScores" in f.description for f in findings)
        assert not any("unsignedValues" in f.description for f in findings)

    def test_negative_fixed_compiler_not_flagged(self, storage_array_fixed_session):
        assert _findings(storage_array_fixed_session, self.RULE) == []


# ------------------------------------------------------------------ assembly
@pytest.fixture(scope="module")
def assembly_session():
    return _session(FIXTURES / "assembly" / "Assembly.sol")


class TestAssembly:
    RULE = "assembly"

    def test_positive_inline_assembly_flagged(self, assembly_session):
        findings = _findings(assembly_session, self.RULE)
        assert len(findings) == 1
        assert "assembly" in findings[0].description
        assert "double" in findings[0].description
        assert findings[0].impact == Impact.INFORMATIONAL

    def test_negative_pure_solidity_not_flagged(self, assembly_session):
        findings = _findings(assembly_session, self.RULE)
        assert not any("NoAssembly" in f.description for f in findings)


# ------------------------------------------------------------ low-level-calls
@pytest.fixture(scope="module")
def low_level_session():
    return _session(FIXTURES / "low-level-calls" / "LowLevelCalls.sol")


class TestLowLevelCalls:
    RULE = "low-level-calls"

    def test_positive_low_level_call_flagged(self, low_level_session):
        findings = _findings(low_level_session, self.RULE)
        assert len(findings) == 1
        assert "call" in findings[0].description
        assert findings[0].additional_fields.get("call") == "call"
        assert findings[0].impact == Impact.INFORMATIONAL

    def test_negative_high_level_call_not_flagged(self, low_level_session):
        findings = _findings(low_level_session, self.RULE)
        assert not any("HighLevelCaller" in f.description for f in findings)


# ----------------------------------------------------------- constable-states
@pytest.fixture(scope="module")
def constable_session():
    return _session(FIXTURES / "constable-states" / "ConstableStates.sol")


class TestConstableStates:
    RULE = "constable-states"

    def test_positive_never_written_initialized_vars_flagged(self, constable_session):
        findings = _findings(constable_session, self.RULE)
        descriptions = [f.description for f in findings]
        assert any("maxFeeBps" in d for d in descriptions)
        assert any("version" in d for d in descriptions)
        assert all(f.impact == Impact.OPTIMIZATION for f in findings)

    def test_negative_written_or_constant_vars_not_flagged(self, constable_session):
        findings = _findings(constable_session, self.RULE)
        descriptions = [f.description for f in findings]
        # written by a setter
        assert not any("changeable" in d for d in descriptions)
        # already declared constant
        assert not any("ALREADY_CONSTANT" in d for d in descriptions)
        # declared without initializer and written later
        assert not any("feeBps" in d for d in descriptions)


# ----------------------------------------------------------- immutable-states
@pytest.fixture(scope="module")
def immutable_session():
    return _session(FIXTURES / "immutable-states" / "ImmutableStates.sol")


class TestImmutableStates:
    RULE = "immutable-states"

    def test_positive_constructor_only_vars_flagged(self, immutable_session):
        findings = _findings(immutable_session, self.RULE)
        descriptions = [f.description for f in findings]
        assert any("owner" in d for d in descriptions)
        assert any("created" in d for d in descriptions)
        # non-compile-time declaration initializer
        assert any("deployedAt" in d for d in descriptions)
        assert all(f.impact == Impact.OPTIMIZATION for f in findings)

    def test_negative_mutated_constable_and_immutable_not_flagged(
        self, immutable_session
    ):
        findings = _findings(immutable_session, self.RULE)
        descriptions = [f.description for f in findings]
        # written outside the constructor
        assert not any("changed" in d for d in descriptions)
        # compile-time initializer -> constable-states, not immutable
        assert not any("maxFeeBps" in d for d in descriptions)
        # already declared immutable
        assert not any("preset" in d for d in descriptions)
        # safe contract: nothing to report
        assert not any("MutableVault" in d for d in descriptions)
