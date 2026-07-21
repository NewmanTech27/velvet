"""Detector batch B tests: delegatecall, token, best-practice,
informational detectors over per-rule fixtures (spec/detectors-catalog.md).

Each rule gets a vulnerable fixture (must fire) and a safe fixture (must
not fire) exercised through a full Velvet session.

Original clean-room implementation.
"""

from __future__ import annotations

from pathlib import Path

from velvet.detectors._batch_b import DETECTORS
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
class TestBatchBMetadata:
    def test_all_rules_present(self):
        assert set(_BY_RULE) == {
            "controlled-delegatecall",
            "delegatecall-loop",
            "arbitrary-send-erc20",
            "unchecked-transfer",
            "unchecked-lowlevel",
            "unchecked-send",
            "weak-prng",
            "timestamp",
            "divide-before-multiply",
            "dead-code",
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
            "controlled-delegatecall": (Impact.HIGH, Confidence.MEDIUM),
            "delegatecall-loop": (Impact.HIGH, Confidence.MEDIUM),
            "arbitrary-send-erc20": (Impact.HIGH, Confidence.HIGH),
            "unchecked-transfer": (Impact.HIGH, Confidence.MEDIUM),
            "unchecked-lowlevel": (Impact.MEDIUM, Confidence.MEDIUM),
            "unchecked-send": (Impact.MEDIUM, Confidence.MEDIUM),
            "weak-prng": (Impact.HIGH, Confidence.MEDIUM),
            "timestamp": (Impact.LOW, Confidence.MEDIUM),
            "divide-before-multiply": (Impact.MEDIUM, Confidence.MEDIUM),
            "dead-code": (Impact.INFORMATIONAL, Confidence.MEDIUM),
        }
        for cls in DETECTORS:
            assert (cls.IMPACT, cls.CONFIDENCE) == expected[cls.RULE], cls.RULE


# ------------------------------------------------------------- delegatecall
class TestControlledDelegatecall:
    def test_positive(self):
        findings = _findings("controlled-delegatecall", "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        # parameter-controlled destination
        assert "exec(address,bytes)" in text
        # caller-settable state destination
        assert "execModule(bytes)" in text
        assert all(f.impact == Impact.HIGH for f in findings)

    def test_negative(self):
        assert _findings("controlled-delegatecall", "Safe") == []


class TestDelegatecallLoop:
    def test_positive(self):
        findings = _findings("delegatecall-loop", "Vulnerable")
        assert len(findings) == 1
        assert "batch(bytes[])" in findings[0].description
        assert findings[0].impact == Impact.HIGH

    def test_negative(self):
        assert _findings("delegatecall-loop", "Safe") == []


# ------------------------------------------------------------------ token
class TestArbitrarySendErc20:
    def test_positive(self):
        findings = _findings("arbitrary-send-erc20", "Vulnerable")
        assert len(findings) == 1
        assert "forward(IERC20,address,uint256)" in findings[0].description
        assert findings[0].confidence == Confidence.HIGH

    def test_negative(self):
        assert _findings("arbitrary-send-erc20", "Safe") == []


class TestUncheckedTransfer:
    def test_positive(self):
        findings = _findings("unchecked-transfer", "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "unstake(IERC20,uint256)" in text
        assert "pull(IERC20,uint256)" in text

    def test_negative(self):
        assert _findings("unchecked-transfer", "Safe") == []


# ----------------------------------------------------------- best-practice
class TestUncheckedLowlevel:
    def test_positive(self):
        findings = _findings("unchecked-lowlevel", "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        # discarded result and captured-but-unused result
        assert "pay(address payable,uint256)" in text
        assert "payCapture(address payable,uint256)" in text

    def test_negative(self):
        assert _findings("unchecked-lowlevel", "Safe") == []


class TestUncheckedSend:
    def test_positive(self):
        findings = _findings("unchecked-send", "Vulnerable")
        assert len(findings) == 1
        assert "refund()" in findings[0].description

    def test_negative(self):
        assert _findings("unchecked-send", "Safe") == []


class TestWeakPrng:
    def test_positive(self):
        findings = _findings("weak-prng", "Vulnerable")
        assert len(findings) == 3
        text = " ".join(f.description for f in findings)
        assert "flip()" in text  # blockhash + timestamp modulo
        assert "pick(uint256)" in text  # block.number modulo
        assert "draw(uint256)" in text  # keccak of block properties modulo

    def test_negative(self):
        assert _findings("weak-prng", "Safe") == []


class TestTimestamp:
    def test_positive(self):
        findings = _findings("timestamp", "Vulnerable")
        assert len(findings) == 6
        text = " ".join(f.description for f in findings)
        assert "claimWindow()" in text  # modulo window
        assert "isMilestone(uint256)" in text  # strict equality
        assert "freshEnough(uint256)" in text  # short-window ordering
        assert "isOpen()" in text  # plain deadline check (broad condition)
        assert "claim()" in text  # require gated by timestamp-derived flag
        assert "_active()" in text  # deadline comparison in internal helper

    def test_negative(self):
        # recording the timestamp is not a comparison/condition
        assert _findings("timestamp", "Safe") == []


class TestDivideBeforeMultiply:
    def test_positive(self):
        findings = _findings("divide-before-multiply", "Vulnerable")
        assert len(findings) == 4
        text = " ".join(f.description for f in findings)
        assert "reward(uint256,uint256)" in text
        assert "fee(uint256,uint256)" in text
        assert "spread(uint256,uint256)" in text  # product feeds a subtraction
        assert "scaled(uint256,uint256)" in text  # division in inline assembly

    def test_negative(self):
        # multiply-first and intentional round-down must not be flagged
        assert _findings("divide-before-multiply", "Safe") == []


# ------------------------------------------------------------ informational
class TestDeadCode:
    def test_positive(self):
        findings = _findings("dead-code", "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "oldHash(bytes)" in text
        # only called by the dead oldHash: not reachable from entry points
        assert "legacyHelper(uint256)" in text

    def test_negative(self):
        assert _findings("dead-code", "Safe") == []

    def test_library_helpers_not_flagged(self):
        # library routines reached through a `using for` library call (and
        # their transitive internal helpers) are reachable, not dead code
        text = " ".join(
            f.description for f in _findings("dead-code", "Library")
        )
        assert "helper(uint256)" not in text
        assert "compute(uint256)" not in text

    def test_reachable_patterns_not_flagged(self):
        # virtual-dispatch overrides, qualified base calls and
        # constructor-called initializers are all reachable
        text = " ".join(
            f.description for f in _findings("dead-code", "Library")
        )
        for reachable in (
            "hook()",
            "_init()",
            "qualified(uint256)",
            "_requirePositive(uint256)",
        ):
            assert reachable not in text

    def test_genuinely_dead_internal_flagged(self):
        findings = _findings("dead-code", "Library")
        assert len(findings) == 1
        assert "orphan(uint256)" in findings[0].description
