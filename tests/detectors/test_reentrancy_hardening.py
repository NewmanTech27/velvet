"""Tests for the reentrancy-family hardening wave.

Covers the three documented v1 limitations of the shared reentrancy core
(src/velvet/detectors/_reentrancy_common.py), now addressed:

1. modifier bodies are inlined around the function body at ``_``;
2. direct internal calls are inlined one level for ordering purposes;
3. the NatSpec ``@custom:security non-reentrant`` tag on state variables is
   consumed (spec/architecture.md §11.3).

Plus unit tests for the NatSpec doc-comment parser (velvet.parsing.natspec).

Original clean-room implementation.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from velvet.detectors._reentrancy_common import natspec_tagged_state_variables
from velvet.detectors.base import Detector
from velvet.detectors.reentrancy_benign import ReentrancyBenign
from velvet.detectors.reentrancy_eth import ReentrancyEth
from velvet.detectors.reentrancy_events import ReentrancyEvents
from velvet.detectors.reentrancy_no_eth import ReentrancyNoEth
from velvet.parsing.natspec import docstring_above, find_tag, has_tag
from velvet.session import Velvet

FIXTURES = (
    Path(__file__).resolve().parent.parent.parent
    / "fixtures"
    / "detectors"
    / "reentrancy-hardening"
)


def _run(detector_class: type[Detector], fixture: Path):
    session = Velvet(str(fixture))
    session.register_detector(detector_class)
    return [f for f in session.run_detectors() if f.check == detector_class.RULE]


def _descriptions(findings) -> list[str]:
    return [f.description for f in findings]


# --------------------------------------------------------------------------
# NatSpec parser unit tests (no compilation needed)
# --------------------------------------------------------------------------
class TestDocstringAbove:
    def test_line_doc_comment(self):
        source = "contract C {\n    /// @custom:security non-reentrant\n    uint256 public x;\n}"
        offset = source.index("uint256 public x")
        doc = docstring_above(source, offset)
        assert doc == "    /// @custom:security non-reentrant"

    def test_block_doc_comment_single_line(self):
        source = "contract C {\n    /** @custom:security non-reentrant */\n    uint256 public x;\n}"
        offset = source.index("uint256 public x")
        assert "/** @custom:security non-reentrant */" in docstring_above(source, offset)

    def test_block_doc_comment_multiline(self):
        source = (
            "contract C {\n"
            "    /**\n"
            "     * @notice a balance\n"
            "     * @custom:security non-reentrant\n"
            "     */\n"
            "    uint256 public x;\n"
            "}"
        )
        offset = source.index("uint256 public x")
        doc = docstring_above(source, offset)
        assert doc.startswith("    /**")
        assert "@custom:security non-reentrant" in doc

    def test_consecutive_line_comments_gathered(self):
        source = (
            "contract C {\n"
            "    /// @notice a balance\n"
            "    /// @custom:security non-reentrant\n"
            "    uint256 public x;\n"
            "}"
        )
        offset = source.index("uint256 public x")
        doc = docstring_above(source, offset)
        assert "@notice" in doc
        assert "@custom:security" in doc

    def test_blank_line_breaks_association(self):
        source = (
            "contract C {\n"
            "    /// @custom:security non-reentrant\n"
            "\n"
            "    uint256 public x;\n"
            "}"
        )
        offset = source.index("uint256 public x")
        assert docstring_above(source, offset) == ""

    def test_code_between_breaks_association(self):
        source = (
            "contract C {\n"
            "    /// @custom:security non-reentrant\n"
            "    uint256 public y;\n"
            "    uint256 public x;\n"
            "}"
        )
        offset = source.index("uint256 public x")
        assert docstring_above(source, offset) == ""

    def test_plain_comments_are_not_docstrings(self):
        source = "contract C {\n    // @custom:security non-reentrant\n    uint256 public x;\n}"
        offset = source.index("uint256 public x")
        assert docstring_above(source, offset) == ""
        source2 = "contract C {\n    //// @custom:security non-reentrant\n    uint256 public x;\n}"
        offset2 = source2.index("uint256 public x")
        assert docstring_above(source2, offset2) == ""

    def test_plain_block_comment_is_not_docstring(self):
        source = "contract C {\n    /* @custom:security non-reentrant */\n    uint256 public x;\n}"
        offset = source.index("uint256 public x")
        assert docstring_above(source, offset) == ""

    def test_same_line_comment_not_associated(self):
        source = "contract C {\n    /** @custom:security non-reentrant */ uint256 public x;\n}"
        offset = source.index("uint256 public x")
        assert docstring_above(source, offset) == ""

    def test_no_comment(self):
        source = "contract C {\n    uint256 public x;\n}"
        offset = source.index("uint256 public x")
        assert docstring_above(source, offset) == ""

    def test_invalid_offsets(self):
        assert docstring_above("", 0) == ""
        assert docstring_above("uint256 x;", 0) == ""
        assert docstring_above("uint256 x;", -1) == ""
        assert docstring_above("uint256 x;", 10_000) == ""


class TestFindTag:
    def test_tag_with_value(self):
        assert find_tag("/// @custom:security non-reentrant", "custom:security") == (
            "non-reentrant"
        )

    def test_bare_tag(self):
        assert find_tag("/// @custom:security", "custom:security") == ""

    def test_tag_absent(self):
        assert find_tag("/// @notice hello", "custom:security") is None
        assert find_tag("", "custom:security") is None

    def test_tag_in_multiline_block(self):
        doc = "/**\n * @notice a balance\n * @custom:security non-reentrant\n */"
        assert find_tag(doc, "custom:security") == "non-reentrant"

    def test_tag_must_start_the_line(self):
        assert find_tag("/// see @custom:security non-reentrant", "custom:security") is None

    def test_similar_prefix_does_not_match(self):
        assert find_tag("/// @custom:security-extra non-reentrant", "custom:security") is None


class TestHasTag:
    def test_value_matches_first_token(self):
        doc = "/// @custom:security non-reentrant (audited externally)"
        assert has_tag(doc, "custom:security", "non-reentrant")

    def test_value_mismatch(self):
        doc = "/// @custom:security reentrant"
        assert not has_tag(doc, "custom:security", "non-reentrant")

    def test_bare_tag_with_value_expected(self):
        assert not has_tag("/// @custom:security", "custom:security", "non-reentrant")

    def test_tag_only(self):
        assert has_tag("/// @custom:security anything", "custom:security")


# --------------------------------------------------------------------------
# 1. modifier-body coverage
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def eth_modifier_vulnerable():
    return _run(ReentrancyEth, FIXTURES / "modifier_vulnerable.sol")


@pytest.fixture(scope="module")
def no_eth_modifier_vulnerable():
    return _run(ReentrancyNoEth, FIXTURES / "modifier_vulnerable.sol")


class TestModifierBodyCoverage:
    def test_eth_call_in_modifier_write_in_body(self, eth_modifier_vulnerable):
        descriptions = _descriptions(eth_modifier_vulnerable)
        assert len(eth_modifier_vulnerable) == 1
        assert any("ModifierVault.balances" in d for d in descriptions)
        assert any("ModifierVault.withdraw()" in d for d in descriptions)

    def test_eth_finding_points_at_modifier_definition_site(
        self, eth_modifier_vulnerable
    ):
        finding = eth_modifier_vulnerable[0]
        node = finding.primary_element
        # The interaction node lives in the `payOut` modifier body, not in
        # `withdraw` — the call is on line 12 of the fixture.
        assert "call" in str(node)
        assert node.source_mapping.lines == [12]

    def test_no_eth_call_in_modifier_write_in_body(self, no_eth_modifier_vulnerable):
        descriptions = _descriptions(no_eth_modifier_vulnerable)
        assert len(no_eth_modifier_vulnerable) == 1
        assert any("ModifierAuction.settled" in d for d in descriptions)
        assert any("ModifierAuction.settle(address)" in d for d in descriptions)

    def test_modifier_cei_and_post_placeholder_safe(self):
        assert _run(ReentrancyEth, FIXTURES / "modifier_safe.sol") == []
        assert _run(ReentrancyNoEth, FIXTURES / "modifier_safe.sol") == []


# --------------------------------------------------------------------------
# 2. one-level internal-call inlining
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def eth_internal_vulnerable():
    return _run(ReentrancyEth, FIXTURES / "internal_vulnerable.sol")


@pytest.fixture(scope="module")
def no_eth_internal_vulnerable():
    return _run(ReentrancyNoEth, FIXTURES / "internal_vulnerable.sol")


class TestInternalCallInlining:
    def test_eth_call_in_helper_write_in_caller(self, eth_internal_vulnerable):
        descriptions = _descriptions(eth_internal_vulnerable)
        assert len(eth_internal_vulnerable) == 2
        assert any("HelperVault.balances" in d for d in descriptions)
        assert any("HelperVault.withdraw()" in d for d in descriptions)

    def test_eth_finding_references_interaction_inside_helper(
        self, eth_internal_vulnerable
    ):
        finding = next(
            f for f in eth_internal_vulnerable if "HelperVault" in f.description
        )
        node = finding.primary_element
        # The reported node is the call inside `_pay` (line 14 of the
        # fixture), while the finding is attributed to `withdraw`.
        assert "call" in str(node)
        assert node.source_mapping.lines == [14]
        assert "HelperVault.withdraw()" in finding.description

    def test_recursive_helper_does_not_hang_and_still_flags(
        self, eth_internal_vulnerable
    ):
        descriptions = _descriptions(eth_internal_vulnerable)
        assert any("RecursiveVault.withdraw(uint256)" in d for d in descriptions)

    def test_recursive_helper_logs_debug_bail(self, caplog):
        with caplog.at_level(logging.DEBUG, logger="velvet.detectors.reentrancy"):
            _run(ReentrancyEth, FIXTURES / "internal_vulnerable.sol")
        assert any(
            "recursive" in record.getMessage() for record in caplog.records
        )

    def test_no_eth_call_in_helper_write_in_caller(self, no_eth_internal_vulnerable):
        descriptions = _descriptions(no_eth_internal_vulnerable)
        assert len(no_eth_internal_vulnerable) == 1
        assert any("HelperAuction.settled" in d for d in descriptions)
        assert any("HelperAuction.settle(address)" in d for d in descriptions)

    def test_cei_through_helper_safe(self):
        assert _run(ReentrancyEth, FIXTURES / "internal_safe.sol") == []
        assert _run(ReentrancyNoEth, FIXTURES / "internal_safe.sol") == []


# --------------------------------------------------------------------------
# 3. NatSpec `@custom:security non-reentrant` consumption
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def eth_natspec_tagged():
    return _run(ReentrancyEth, FIXTURES / "natspec_tagged.sol")


class TestNatspecTagConsumption:
    def test_tagged_variable_excluded_untagged_still_flagged(
        self, eth_natspec_tagged
    ):
        descriptions = _descriptions(eth_natspec_tagged)
        assert len(eth_natspec_tagged) == 1
        assert any("TaggedVault.untagged" in d for d in descriptions)
        assert any("withdrawUntagged" in d for d in descriptions)
        assert not any("TaggedVault.balances" in d for d in descriptions)

    def test_block_doc_tag_excludes_no_eth_finding(self):
        assert _run(ReentrancyNoEth, FIXTURES / "natspec_tagged.sol") == []

    def test_helper_collects_tagged_variable_ids(self):
        session = Velvet(str(FIXTURES / "natspec_tagged.sol"))
        session.register_detector(ReentrancyEth)
        session.run_detectors()
        unit = session.compilation_units[0]
        tagged = natspec_tagged_state_variables(unit)
        names = {
            v.name
            for v in unit.state_variables
            if id(v) in tagged
        }
        assert names == {"balances", "settled"}


# --------------------------------------------------------------------------
# bonus: helper writes/events reachable after the call
# --------------------------------------------------------------------------
class TestHelperWritesAndEvents:
    def test_write_inside_helper_after_call_is_flagged_benign(self):
        findings = _run(ReentrancyBenign, FIXTURES / "helper_writes_events.sol")
        descriptions = _descriptions(findings)
        assert len(findings) == 1
        assert any("HelperEpoch.epoch" in d for d in descriptions)

    def test_event_after_call_through_helper_write_is_flagged(self):
        findings = _run(ReentrancyEvents, FIXTURES / "helper_writes_events.sol")
        descriptions = _descriptions(findings)
        assert len(findings) == 1
        assert any("HelperEpoch.epoch" in d for d in descriptions)


# --------------------------------------------------------------------------
# bounded transitive inlining: deep internal chains, qualified static
# calls, virtual dispatch, and ERC-7201 storage regions
# --------------------------------------------------------------------------
class TestBoundedTransitiveInlining:
    def test_no_eth_call_three_levels_deep_write_after(self):
        findings = _run(ReentrancyNoEth, FIXTURES / "deep_chain.sol")
        descriptions = _descriptions(findings)
        assert len(findings) == 1
        assert any("DeepChainVault.balances" in d for d in descriptions)
        assert any("DeepChainVault.ping" in d for d in descriptions)

    def test_state_dependent_event_after_call_in_nested_helper(self):
        findings = _run(ReentrancyEvents, FIXTURES / "deep_chain.sol")
        descriptions = _descriptions(findings)
        # advance, _wrap and _advanceInner each emit EpochAdvanced after
        # the call through their own chain.
        assert len(findings) == 3
        assert all("DeepChainVault.epoch" in d for d in descriptions)
        assert any("advance" in d for d in descriptions)

    def test_mutex_at_deepest_level_still_suppresses(self):
        findings = _run(ReentrancyNoEth, FIXTURES / "deep_mutex.sol")
        assert findings == []

    def test_qualified_static_call_is_inlined(self):
        findings = _run(ReentrancyNoEth, FIXTURES / "qualified_call.sol")
        descriptions = _descriptions(findings)
        assert len(findings) == 2
        assert any("QualifiedVault.ping" in d for d in descriptions)
        assert any("OverrideVault.poke" in d for d in descriptions)

    def test_virtual_dispatch_resolves_most_derived_override(self):
        findings = _run(ReentrancyNoEth, FIXTURES / "qualified_call.sol")
        descriptions = _descriptions(findings)
        # The call only exists in OverrideVault._settleInner; without
        # virtual dispatch resolution `poke` would be missed.
        assert any("OverrideVault.poke" in d for d in descriptions)

    def test_diamond_storage_region_write_after_call(self):
        findings = _run(ReentrancyNoEth, FIXTURES / "diamond_storage.sol")
        descriptions = _descriptions(findings)
        assert len(findings) == 1
        assert any("AppStorage" in d for d in descriptions)
        assert any("DiamondVault.ping" in d for d in descriptions)
        # DiamondVaultChecked.ping writes before the call (CEI): clean.
        assert not any("DiamondVaultChecked.ping" in d for d in descriptions)

    def test_base_qualified_call_into_own_override_is_static(self):
        # `ERC20LikeBase._updateSupply(...)` inside the override is a
        # statically-bound internal jump to the base body (which holds the
        # ERC-7201 region write).  Resolving it to the most-derived override
        # would mark the chain recursive and drop the write: the deep-chain
        # region finding would be lost (the CMTAT 43 -> 0 regression).
        findings = _run(ReentrancyNoEth, FIXTURES / "base_qualified_override.sol")
        descriptions = _descriptions(findings)
        assert len(findings) == 1
        assert any("RegionToken.burnAndMint" in d for d in descriptions)
        assert any("ERC20Storage" in d for d in descriptions)

    def test_base_qualified_call_cei_variant_clean(self):
        # Same chain, but the region write lands before the snapshot call
        # (checks-effects-interactions): no write-after-call finding, and the
        # base-qualified static resolution must not invent one either.
        findings = _run(ReentrancyNoEth, FIXTURES / "base_qualified_override.sol")
        descriptions = _descriptions(findings)
        assert not any("SafeRegionToken" in d for d in descriptions)
