"""Detector batch F tests: oracle/randomness, L2/security,
complexity/best-practice and gas detectors over per-rule fixtures
(spec/detectors-catalog.md — normative entries).

Each rule gets a vulnerable fixture (must fire) and a safe fixture (must
not fire) exercised through a full Velvet session.

Original clean-room implementation.
"""

from __future__ import annotations

from pathlib import Path

from velvet.detectors._batch_f import DETECTORS
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
class TestBatchFMetadata:
    def test_all_rules_present(self):
        assert set(_BY_RULE) == {
            "pyth-unchecked-confidence",
            "pyth-unchecked-publishtime",
            "pyth-deprecated-functions",
            "chronicle-unchecked-price",
            "chainlink-feed-registry",
            "gelato-unprotected-randomness",
            "out-of-order-retryable",
            "return-bomb",
            "cyclomatic-complexity",
            "void-cst",
            "too-many-digits",
            "boolean-equal",
            "cache-array-length",
            "external-function",
            "costly-loop",
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
            "pyth-unchecked-confidence": (Impact.MEDIUM, Confidence.HIGH),
            "pyth-unchecked-publishtime": (Impact.MEDIUM, Confidence.HIGH),
            "pyth-deprecated-functions": (Impact.MEDIUM, Confidence.HIGH),
            "chronicle-unchecked-price": (Impact.MEDIUM, Confidence.MEDIUM),
            "chainlink-feed-registry": (Impact.LOW, Confidence.HIGH),
            "gelato-unprotected-randomness": (Impact.MEDIUM, Confidence.MEDIUM),
            "out-of-order-retryable": (Impact.MEDIUM, Confidence.MEDIUM),
            "return-bomb": (Impact.LOW, Confidence.MEDIUM),
            "cyclomatic-complexity": (Impact.INFORMATIONAL, Confidence.HIGH),
            "void-cst": (Impact.LOW, Confidence.HIGH),
            "too-many-digits": (Impact.INFORMATIONAL, Confidence.MEDIUM),
            "boolean-equal": (Impact.INFORMATIONAL, Confidence.HIGH),
            "cache-array-length": (Impact.OPTIMIZATION, Confidence.HIGH),
            "external-function": (Impact.OPTIMIZATION, Confidence.HIGH),
            "costly-loop": (Impact.INFORMATIONAL, Confidence.MEDIUM),
        }
        for cls in DETECTORS:
            assert (cls.IMPACT, cls.CONFIDENCE) == expected[cls.RULE], cls.RULE


# --------------------------------------------------- pyth-deprecated-functions
class TestPythDeprecatedFunctions:
    RULE = "pyth-deprecated-functions"

    def test_positive_deprecated_getters_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "getPrice" in text
        assert "getEmaPrice" in text

    def test_negative_modern_getters_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# --------------------------------------------------- pyth-unchecked-confidence
class TestPythUncheckedConfidence:
    RULE = "pyth-unchecked-confidence"

    def test_positive_unvalidated_conf_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "borrowValue" in text  # conf never extracted
        assert "emaValue" in text  # conf extracted but never validated

    def test_negative_bounded_conf_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# -------------------------------------------------- pyth-unchecked-publishtime
class TestPythUncheckedPublishtime:
    RULE = "pyth-unchecked-publishtime"

    def test_positive_unvalidated_publishtime_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "rate" in text  # publishTime never extracted
        assert "spot" in text  # publishTime extracted but never validated

    def test_negative_freshness_enforced_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ---------------------------------------------------- chronicle-unchecked-price
class TestChronicleUncheckedPrice:
    RULE = "chronicle-unchecked-price"

    def test_positive_raw_read_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "ethUsd" in text
        assert "twap" in text

    def test_negative_validity_checked_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ----------------------------------------------------- chainlink-feed-registry
class TestChainlinkFeedRegistry:
    RULE = "chainlink-feed-registry"

    def test_positive_registry_usage_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf" in text  # known address
        assert "latestRoundData" in text  # two-address registry query

    def test_negative_direct_aggregator_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------- gelato-unprotected-randomness
class TestGelatoUnprotectedRandomness:
    RULE = "gelato-unprotected-randomness"

    def test_positive_unprotected_request_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 1
        assert "spin" in findings[0].description

    def test_negative_owner_restricted_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------------ out-of-order-retryable
class TestOutOfOrderRetryable:
    RULE = "out-of-order-retryable"

    def test_positive_two_tickets_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 1
        assert "claimThenUnstake" in findings[0].description
        assert "2" in findings[0].description

    def test_negative_single_ticket_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# --------------------------------------------------------------- return-bomb
class TestReturnBomb:
    RULE = "return-bomb"

    def test_positive_unbounded_returndata_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "fetch" in text  # (bool, bytes) = oracle.call
        assert "run" in text  # (bool, bytes) = impl.delegatecall

    def test_negative_discarded_or_capped_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------------- cyclomatic-complexity
class TestCyclomaticComplexity:
    RULE = "cyclomatic-complexity"

    def test_positive_complex_function_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 1
        assert "route" in findings[0].description
        assert findings[0].additional_fields["cyclomatic_complexity"] > 11

    def test_negative_simple_functions_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------------------------ void-cst
class TestVoidCst:
    RULE = "void-cst"

    def test_positive_noop_base_call_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 1
        assert "Base" in findings[0].description

    def test_negative_real_or_absent_base_call_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------------------- too-many-digits
class TestTooManyDigits:
    RULE = "too-many-digits"

    def test_positive_long_literals_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 4
        text = " ".join(f.description for f in findings)
        assert "100000000000000000000" in text  # CAP (21 digits)
        assert "10000000" in text  # RATE (8 digits)
        assert "50000000000000000000" in text  # quota (20 digits)
        assert "0xFFFFFFFF00000000FFFFFFFF00000000" in text  # 32 hex digits

    def test_negative_readable_literals_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# --------------------------------------------------------------- boolean-equal
class TestBooleanEqual:
    RULE = "boolean-equal"

    def test_positive_boolean_literal_comparisons_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 3
        text = " ".join(f.description for f in findings)
        assert "open" in text  # locked == false
        assert "eligible" in text  # (score > 5) == true
        assert "deposit" in text  # require(locked == false)

    def test_negative_direct_booleans_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ----------------------------------------------------------- cache-array-length
class TestCacheArrayLength:
    RULE = "cache-array-length"

    def test_positive_length_reread_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "sum" in text
        assert "countAbove" in text

    def test_negative_cached_or_memory_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------------------ external-function
class TestExternalFunction:
    RULE = "external-function"

    def test_positive_public_only_functions_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "mint" in text
        assert "burn" in text

    def test_negative_internally_called_or_external_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []

    def test_negative_interface_implementation_without_override_keyword(self):
        # Solidity does not require `override` to implement an interface
        # function; the visibility is constrained by the interface.
        findings = _findings(self.RULE, "Safe")
        assert not any("LeafToken.mint" in f.description for f in findings)

    def test_negative_abstract_or_inherited_contracts_not_flagged(self):
        # Abstract contracts and contracts with derived contracts are
        # inheritance APIs; their public functions may be required `public`
        # by consumers outside the analyzed set.
        findings = _findings(self.RULE, "Safe")
        assert not any("AbstractToken.mint" in f.description for f in findings)
        assert not any("BaseToken.mint" in f.description for f in findings)


# ----------------------------------------------------------------- costly-loop
class TestCostlyLoop:
    RULE = "costly-loop"

    def test_positive_state_and_msg_value_in_loop_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 3
        text = " ".join(f.description for f in findings)
        assert "accumulate" in text  # total accumulated in a loop
        assert "msg.value" in text  # msg.value read in a loop

    def test_negative_local_accumulator_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []
