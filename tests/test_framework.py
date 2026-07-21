"""Framework tests: detector contract, session, reference detectors,
JSON/SARIF outputs, filtering (api-surface.md §5, §9; architecture.md §8-11).

Original clean-room implementation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from velvet.detectors import BUILTIN_DETECTORS
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.filtering import parse_suppressions, should_fail
from velvet.session import Analyzer, Velvet

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ------------------------------------------------------------- metadata
class TestDetectorContract:
    def test_builtin_metadata(self):
        for cls in BUILTIN_DETECTORS:
            assert cls.RULE and isinstance(cls.RULE, str)
            assert cls.TITLE
            assert isinstance(cls.IMPACT, Impact)
            assert isinstance(cls.CONFIDENCE, Confidence)
            assert isinstance(cls.DOCS, DetectorDocs)
            assert cls.DOCS.url.startswith("http")
            assert cls.DOCS.description
            assert cls.DOCS.exploit_scenario
            assert cls.DOCS.recommendation

    def test_missing_rule_rejected(self):
        class Broken(Detector):
            RULE = ""

            def analyze(self):
                return []

        with pytest.raises(ValueError):
            Broken(None, None)  # type: ignore[arg-type]

    def test_finding_builder_and_id(self):
        class Toy(Detector):
            RULE = "toy"
            TITLE = "Toy"
            IMPACT = Impact.LOW
            CONFIDENCE = Confidence.HIGH
            DOCS = DetectorDocs(
                url="https://example.com", title="t", description="d",
                exploit_scenario="e", recommendation="r",
            )

            def analyze(self):
                return []

        detector = Toy(None, None)  # type: ignore[arg-type]
        finding = detector.finding(["hello ", "world"])
        assert isinstance(finding, Finding)
        assert finding.description == "hello world"
        assert finding.check == "toy"
        assert finding.impact == Impact.LOW
        assert len(finding.id) == 64
        # stable: same rule + elements -> same id
        assert finding.id == detector.finding(["hello ", "world"]).id


# ----------------------------------------------------------------- session
@pytest.fixture(scope="module")
def tx_origin_session():
    return Velvet(str(FIXTURES / "detectors" / "TxOrigin.sol"))


class TestSession:
    def test_analyzer_alias(self, tx_origin_session):
        assert Analyzer is Velvet
        assert isinstance(tx_origin_session, Analyzer)

    def test_model_accessors(self, tx_origin_session):
        s = tx_origin_session
        assert len(s.compilation_units) == 1
        assert s.contracts
        assert s.contracts_derived
        assert s.get_contract_from_name("TxOriginWallet") is not None
        assert s.filename_lookup("TxOrigin.sol") is not None
        assert "contract TxOriginWallet" in s.source_code("TxOrigin.sol")

    def test_register_unregister(self, tx_origin_session):
        s = tx_origin_session
        from velvet.detectors.tx_origin import TxOrigin

        s.unregister_detector(TxOrigin)
        assert all(d.RULE != "tx-origin" for d in s.registered_detectors)
        s.register_detector(TxOrigin)
        assert any(d.RULE == "tx-origin" for d in s.registered_detectors)
        # re-registering the SAME class is idempotent; a DIFFERENT class
        # reusing the rule id is an error
        s.register_detector(TxOrigin)
        count = sum(d.RULE == "tx-origin" for d in s.registered_detectors)
        assert count == 1

        class Imposter(TxOrigin):
            pass

        with pytest.raises(ValueError):
            s.register_detector(Imposter)

    def test_detector_grouping_by_impact(self, tx_origin_session):
        s = tx_origin_session
        assert s.detectors_medium
        assert s.detectors_informational


# ---------------------------------------------------- reference detectors
class TestTxOriginDetector:
    def test_positive(self, tx_origin_session):
        findings = [f for f in tx_origin_session.run_detectors() if f.check == "tx-origin"]
        # emergencyDrain + onlyOrigin modifier (drainViaModifier uses the modifier)
        assert len(findings) >= 2
        assert all(f.impact == Impact.MEDIUM for f in findings)

    def test_negative_msg_sender_not_flagged(self, tx_origin_session):
        findings = [f for f in tx_origin_session.run_detectors() if f.check == "tx-origin"]
        assert not any("safeDrain" in f.description for f in findings)


class TestPragmaDetector:
    def test_positive_inconsistent(self):
        session = Velvet(str(FIXTURES / "detectors" / "pragma"))
        findings = [f for f in session.run_detectors() if f.check == "pragma"]
        assert findings
        assert any("inconsistent" in f.description for f in findings)

    def test_negative_single_pragma(self, tx_origin_session):
        findings = [f for f in tx_origin_session.run_detectors() if f.check == "pragma"]
        assert findings == []


class TestSolcVersionDetector:
    def test_positive_outdated_and_complex(self):
        session = Velvet(str(FIXTURES / "detectors" / "SolcVersion.sol"))
        findings = [f for f in session.run_detectors() if f.check == "solc-version"]
        assert len(findings) == 1
        assert "floor" in findings[0].description

    def test_negative_modern_pragma(self, tx_origin_session):
        findings = [
            f for f in tx_origin_session.run_detectors() if f.check == "solc-version"
        ]
        assert findings == []


# ------------------------------------------------------------------ outputs
class TestJsonOutput:
    def test_schema_keys(self, tx_origin_session):
        from velvet.outputs.json_out import build_json_output

        findings = tx_origin_session.run_detectors()
        doc = build_json_output(tx_origin_session, findings)
        assert doc["success"] is True
        assert doc["error"] is None
        detectors = doc["results"]["detectors"]
        assert detectors
        for entry in detectors:
            for key in (
                "check",
                "impact",
                "confidence",
                "description",
                "markdown",
                "first_markdown_element",
                "id",
                "elements",
            ):
                assert key in entry, key
        first = detectors[0]
        element = next(e for e in first["elements"] if "source_mapping" in e)
        for key in (
            "start",
            "length",
            "filename_relative",
            "filename_absolute",
            "filename_short",
            "filename_used",
            "lines",
            "starting_column",
            "ending_column",
        ):
            assert key in element["source_mapping"], key
        # parent chain: node -> function -> contract
        node_el = next(e for e in first["elements"] if e["type"] == "node")
        parent = node_el["type_specific_fields"]["parent"]
        assert parent["type"] == "function"
        assert "signature" in parent["type_specific_fields"]
        assert parent["type_specific_fields"]["parent"]["type"] == "contract"

    def test_determinism(self, tx_origin_session):
        from velvet.outputs.json_out import build_json_output, dump_json

        findings = tx_origin_session.run_detectors()
        first = dump_json(build_json_output(tx_origin_session, findings))
        findings2 = tx_origin_session.run_detectors()
        second = dump_json(build_json_output(tx_origin_session, findings2))
        assert first == second

    def test_json_types_sections(self, tx_origin_session):
        from velvet.outputs.json_out import build_json_output

        doc = build_json_output(
            tx_origin_session, [], json_types=["list-detectors", "compilations"]
        )
        assert "list-detectors" in doc["results"]
        assert "compilations" in doc["results"]
        rules = {d["check"] for d in doc["results"]["list-detectors"]}
        assert {"tx-origin", "pragma", "solc-version"} <= rules


class TestSarif:
    def test_structure(self, tx_origin_session):
        from velvet.outputs.sarif import build_sarif

        findings = tx_origin_session.run_detectors()
        sarif = build_sarif(tx_origin_session, findings)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        run = sarif["runs"][0]
        driver = run["tool"]["driver"]
        assert driver["name"] == "velvet"
        rules = {r["id"] for r in driver["rules"]}
        assert rules == {f.check for f in findings}
        for result in run["results"]:
            assert result["ruleId"] in rules
            assert result["level"] in ("error", "warning", "note")
            assert result["partialFingerprints"]["velvet/finding-id"]
            location = result["locations"][0]["physicalLocation"]
            assert location["artifactLocation"]["uri"]
            assert location["region"]["startLine"] >= 1

    def test_level_mapping(self, tx_origin_session):
        from velvet.outputs.sarif import build_sarif

        sarif = build_sarif(tx_origin_session, tx_origin_session.run_detectors())
        levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
        assert levels["tx-origin"] == "warning"  # MEDIUM -> warning


# ---------------------------------------------------------------- filtering
class TestFiltering:
    def test_parse_suppressions(self):
        text = "a\n// velvet-disable-next-line tx-origin\nb\n// velvet-disable-start r\nx\n// velvet-disable-end r\n"
        sup = parse_suppressions(text)
        assert sup.is_suppressed("tx-origin", 3)
        assert not sup.is_suppressed("other", 3)
        assert sup.is_suppressed("r", 5)
        assert not sup.is_suppressed("r", 6)

    def test_suppressed_findings_removed(self):
        session = Velvet(str(FIXTURES / "detectors" / "Suppression.sol"))
        findings = [f for f in session.run_detectors() if f.check == "tx-origin"]
        # only notSuppressed survives
        assert len(findings) == 1
        assert "notSuppressed" in findings[0].description

    def test_filter_paths(self, tx_origin_session):
        session = Velvet(
            str(FIXTURES / "detectors" / "TxOrigin.sol"), filter_paths=["TxOrigin"]
        )
        assert session.run_detectors() == []

    def test_include_paths(self, tx_origin_session):
        session = Velvet(
            str(FIXTURES / "detectors" / "TxOrigin.sol"), include_paths=["Nowhere"]
        )
        assert session.run_detectors() == []

    def test_fail_on_policy(self, tx_origin_session):
        # Scope to the tx-origin detector: the fixture now also triggers
        # legitimate HIGH findings from other built-in detectors.
        findings = [
            f for f in tx_origin_session.run_detectors() if f.check == "tx-origin"
        ]
        assert should_fail(findings, "pedantic") is True
        assert should_fail(findings, "low") is True  # MEDIUM counts
        assert should_fail(findings, "medium") is True
        assert should_fail(findings, "high") is False  # no HIGH findings
        assert should_fail(findings, "none") is False
        assert should_fail([], "pedantic") is False
        with pytest.raises(ValueError):
            should_fail(findings, "bogus")
