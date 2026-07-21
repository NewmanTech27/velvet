"""Detector batch E tests: loop/call, constant-condition, write,
token-interface and event detectors over per-rule fixtures
(spec/detectors-catalog.md — normative entries).

Each rule gets a vulnerable fixture (must fire) and a safe fixture (must
not fire) exercised through a full Velvet session.

Original clean-room implementation.
"""

from __future__ import annotations

from pathlib import Path

from velvet.detectors._batch_e import DETECTORS
from velvet.detectors.base import Confidence, DetectorDocs, Impact
from velvet.session import Velvet

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "detectors"

_BY_RULE = {detector.RULE: detector for detector in DETECTORS}

#: Lazily-built sessions: (rule, "Vulnerable"|"Safe") -> Velvet.
_SESSIONS: dict[tuple[str, str], Velvet] = {}


def _session(rule: str, kind: str) -> Velvet:
    key = (rule, kind)
    if key not in _SESSIONS:
        session = Velvet(str(FIXTURES / rule / f"{kind}.sol"))
        session.register_detector(_BY_RULE[rule])
        _SESSIONS[key] = session
    return _SESSIONS[key]


def _findings(rule: str, kind: str):
    session = _session(rule, kind)
    return [f for f in session.run_detectors() if f.check == rule]


# ------------------------------------------------------------- metadata
class TestBatchEMetadata:
    def test_all_rules_present(self):
        assert set(_BY_RULE) == {
            "calls-loop",
            "unused-return",
            "boolean-cst",
            "tautology",
            "tautological-compare",
            "incorrect-equality",
            "write-after-write",
            "mapping-deletion",
            "incorrect-modifier",
            "domain-separator-collision",
            "erc20-interface",
            "erc721-interface",
            "erc20-indexed",
            "missing-inheritance",
            "events-access",
        }

    def test_metadata_contract(self):
        for cls in DETECTORS:
            assert cls.RULE and isinstance(cls.RULE, str)
            assert cls.TITLE
            assert isinstance(cls.IMPACT, Impact)
            assert isinstance(cls.CONFIDENCE, Confidence)
            assert isinstance(cls.DOCS, DetectorDocs)
            assert cls.DOCS.url.startswith("http")
            assert cls.DOCS.description
            assert cls.DOCS.exploit_scenario
            assert cls.DOCS.recommendation

    def test_catalog_classification(self):
        expected = {
            "calls-loop": (Impact.LOW, Confidence.MEDIUM),
            "unused-return": (Impact.MEDIUM, Confidence.MEDIUM),
            "boolean-cst": (Impact.MEDIUM, Confidence.MEDIUM),
            "tautology": (Impact.MEDIUM, Confidence.HIGH),
            "tautological-compare": (Impact.MEDIUM, Confidence.HIGH),
            "incorrect-equality": (Impact.MEDIUM, Confidence.HIGH),
            "write-after-write": (Impact.MEDIUM, Confidence.HIGH),
            "mapping-deletion": (Impact.MEDIUM, Confidence.HIGH),
            "incorrect-modifier": (Impact.LOW, Confidence.HIGH),
            "domain-separator-collision": (Impact.MEDIUM, Confidence.HIGH),
            "erc20-interface": (Impact.MEDIUM, Confidence.HIGH),
            "erc721-interface": (Impact.MEDIUM, Confidence.HIGH),
            "erc20-indexed": (Impact.INFORMATIONAL, Confidence.HIGH),
            "missing-inheritance": (Impact.INFORMATIONAL, Confidence.HIGH),
            "events-access": (Impact.LOW, Confidence.MEDIUM),
        }
        for cls in DETECTORS:
            assert (cls.IMPACT, cls.CONFIDENCE) == expected[cls.RULE], cls.RULE


# -------------------------------------------------------------- calls-loop
class TestCallsLoop:
    RULE = "calls-loop"

    def test_positive_external_calls_in_loops_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 7
        text = " ".join(f.description for f in findings)
        assert "distribute" in text  # transfer in a for loop
        assert "airdrop" in text  # high-level token call in a while loop
        assert "notify" in text  # low-level call in a loop
        assert "_payOne" in text  # external call in an internal helper of a loop
        assert "DividendsOverride._hook" in text  # override reached from a loop
        assert "firstMatch" in text  # call on a return path inside the loop body
        assert "sweepAll" in text  # call in a do-while body

    def test_negative_pull_pattern_and_library_calls_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ----------------------------------------------------------- unused-return
class TestUnusedReturn:
    RULE = "unused-return"

    def test_positive_discarded_results_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "Math.twice" in text
        assert "latestPrice" in text

    def test_negative_used_or_mutating_calls_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------------------- boolean-cst
class TestBooleanCst:
    RULE = "boolean-cst"

    def test_positive_constant_conditions_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 3
        text = " ".join(f.description for f in findings)
        assert "deposit" in text  # if (false)
        assert "isActive" in text  # flag || true
        assert "eligible" in text  # score > 10 && false

    def test_negative_idiomatic_while_true_with_break_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# --------------------------------------------------------------- tautology
class TestTautology:
    RULE = "tautology"

    def test_positive_range_fixed_comparisons_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 4
        text = " ".join(f.description for f in findings)
        assert "checkBid" in text  # uint256 >= 0, always true
        assert "smallEnough" in text  # uint8 < 512, always true
        assert "underflowed" in text  # uint256 < 0, always false
        assert "alwaysDifferent" in text  # uint16 == 0x10001, always false
        assert any("always true" in f.description for f in findings)
        assert any("always false" in f.description for f in findings)

    def test_negative_in_range_comparisons_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------------ tautological-compare
class TestTautologicalCompare:
    RULE = "tautological-compare"

    def test_positive_identical_operands_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 4
        text = " ".join(f.description for f in findings)
        assert "valid" in text  # amount <= amount
        assert "balanced" in text  # a + b == a + b
        assert "changed" in text  # x != x
        assert "atCap" in text  # cap >= cap

    def test_negative_distinct_operands_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []

    def test_negative_safe_cast_roundtrip_not_flagged(self):
        # `downcasted == value` after a narrowing conversion is a genuine
        # guard, not a tautology (conversions are not value-preserving).
        findings = _findings(self.RULE, "Safe")
        assert not any("toUint104" in f.description for f in findings)


# ------------------------------------------------------- incorrect-equality
class TestIncorrectEquality:
    RULE = "incorrect-equality"

    def test_positive_balance_equalities_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 3
        text = " ".join(f.description for f in findings)
        assert "finalize" in text  # address(this).balance == GOAL
        assert "untouched" in text  # balanceOf == 0
        assert "exactMatch" in text  # cached balance != GOAL

    def test_negative_range_comparisons_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# -------------------------------------------------------- write-after-write
class TestWriteAfterWrite:
    RULE = "write-after-write"

    def test_positive_dead_writes_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 3
        text = " ".join(f.description for f in findings)
        assert "fee" in text  # fee = 100 overwritten by the ternary
        assert "lastFee" in text  # state variable written twice
        assert "rate" in text  # local overwritten before use

    def test_negative_read_between_writes_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# --------------------------------------------------------- mapping-deletion
class TestMappingDeletion:
    RULE = "mapping-deletion"

    def test_positive_delete_on_struct_with_mapping_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "Profile" in text  # direct mapping member
        assert "Nested" in text  # transitive mapping member

    def test_negative_plain_deletions_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------------- incorrect-modifier
class TestIncorrectModifier:
    RULE = "incorrect-modifier"

    def test_positive_fallthrough_modifiers_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "onlyIfOwner" in text  # if without else
        assert "unlessClosed" in text  # early return path

    def test_negative_reverting_or_placeholder_paths_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------ domain-separator-collision
class TestDomainSeparatorCollision:
    RULE = "domain-separator-collision"

    def test_positive_colliding_declarations_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "BadOverloadToken" in text  # DOMAIN_SEPARATOR(bytes32)
        assert "BadReturnToken" in text  # returns (uint256)

    def test_negative_conforming_or_non_permit_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ----------------------------------------------------------- erc20-interface
class TestErc20Interface:
    RULE = "erc20-interface"

    def test_positive_wrong_return_types_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 3
        text = " ".join(f.description for f in findings)
        assert "transfer(address,uint256)" in text  # missing bool return
        assert "approve(address,uint256)" in text  # returns uint256
        assert "totalSupply()" in text  # returns bool

    def test_negative_conforming_surface_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ---------------------------------------------------------- erc721-interface
class TestErc721Interface:
    RULE = "erc721-interface"

    def test_positive_wrong_return_types_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 3
        text = " ".join(f.description for f in findings)
        assert "ownerOf" in text  # returns bool instead of address
        assert "isApprovedForAll" in text  # returns uint256 instead of bool
        assert "getApproved" in text  # returns bool instead of address

    def test_negative_conforming_surface_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------------------- erc20-indexed
class TestErc20Indexed:
    RULE = "erc20-indexed"

    def test_positive_unindexed_address_params_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "Transfer" in text  # neither address indexed
        assert "Approval" in text  # spender not indexed

    def test_negative_indexed_events_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------------- missing-inheritance
class TestMissingInheritance:
    RULE = "missing-inheritance"

    def test_positive_uninheritied_implementation_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 1
        assert "Vault" in findings[0].description
        assert "IVault" in findings[0].description

    def test_negative_declared_or_partial_inheritance_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------------------- events-access
class TestEventsAccess:
    RULE = "events-access"

    def test_positive_silent_role_changes_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "transferGovernance" in text  # governor change, no event
        assert "rotateAdmin" in text  # admin change via internal helper

    def test_negative_announced_changes_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []
