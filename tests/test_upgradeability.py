"""Tests for ``velvet-check-upgradeability`` (spec/printers-and-tools.md §B.2).

Covers the full 17-check catalog (positive and negative per check), the
V1-only / V2 / proxy modes, the JSON ``upgradeability-check`` envelope,
exit codes, and the console-script entry point.

Original clean-room implementation.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from velvet.session import Velvet
from velvet.tools import check_upgradeability as cu
from velvet.tools.common import function_selector, keccak256

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "tools" / "upgradeability"


# ---------------------------------------------------------------------------
# module-scoped sessions (one solc run per target)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def session() -> Velvet:
    return Velvet(str(FIXTURES))


@pytest.fixture(scope="module")
def noinit_session() -> Velvet:
    return Velvet(str(FIXTURES / "NoInitializable.sol"))


def _review(session: Velvet, name: str, v2: str | None = None, proxy: str | None = None):
    context = cu.ReviewContext(
        session=session,
        contract=cu.find_contract(session, name),
        v2_contract=cu.find_contract(session, v2) if v2 else None,
        proxy_contract=cu.find_contract(session, proxy) if proxy else None,
    )
    return cu.review(context)


def _keys(report, bucket):
    return {
        key
        for key, findings in getattr(report, f"{bucket}_findings").items()
        if findings
    }


# ---------------------------------------------------------------------------
# keccak / selector primitives
# ---------------------------------------------------------------------------


class TestKeccak:
    def test_empty_digest_vector(self):
        assert keccak256(b"").hex() == (
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        )

    def test_selector_vectors(self):
        assert function_selector("transfer(address,uint256)").hex() == "a9059cbb"
        assert function_selector("approve(address,uint256)").hex() == "095ea7b3"
        assert function_selector("initialize(address)").hex() == "c4d66de8"

    def test_documented_collision_pair(self):
        # published selector-clashing example pair
        assert function_selector("burn(uint256)") == function_selector(
            "collate_propagate_storage(bytes16)"
        )


# ---------------------------------------------------------------------------
# catalog integrity (spec §B.2.2)
# ---------------------------------------------------------------------------


class TestCatalog:
    def test_seventeen_documented_checks(self):
        assert len(cu.CHECKS) == 17

    @pytest.mark.parametrize(
        "key,impact,needs_proxy,needs_v2",
        [
            ("became-constant", "High", False, True),
            ("function-id-collision", "High", True, False),
            ("function-shadowing", "High", True, False),
            ("missing-calls", "High", False, False),
            ("missing-init-modifier", "High", False, False),
            ("multiple-calls", "High", False, False),
            ("order-vars-contracts", "High", False, True),
            ("order-vars-proxy", "High", True, False),
            ("variables-initialized", "High", False, False),
            ("were-constant", "High", False, True),
            ("extra-vars-proxy", "Medium", True, False),
            ("missing-variables", "Medium", False, True),
            ("extra-vars-v2", "Informational", False, True),
            ("init-inherited", "Informational", False, False),
            ("init-missing", "Informational", False, False),
            ("initialize-target", "Informational", False, False),
            ("initializer-missing", "Informational", False, False),
        ],
    )
    def test_check_metadata(self, key, impact, needs_proxy, needs_v2):
        spec = cu.CHECKS_BY_KEY[key]
        assert spec.impact == impact
        assert spec.needs_proxy is needs_proxy
        assert spec.needs_v2 is needs_v2
        assert not spec.enhancement

    def test_enhancements_are_separate(self):
        assert all(e.enhancement for e in cu.ENHANCEMENTS)
        assert not set(cu.ENHANCEMENTS_BY_KEY) & set(cu.CHECKS_BY_KEY)


# ---------------------------------------------------------------------------
# V1-only mode: the model implementation
# ---------------------------------------------------------------------------


class TestGoodImpl:
    @pytest.fixture
    def report(self, session):
        return _review(session, "GoodImpl")

    def test_no_failures(self, report):
        assert report.ok
        assert report.failures == 0

    def test_initialize_target_reported(self, report):
        findings = report.findings_for("v1", "initialize-target")
        assert len(findings) == 1
        assert "GoodImpl.initialize()" in findings[0].message
        assert findings[0].status == cu.INFO

    def test_initializer_protection_checks_pass(self, report):
        # no findings at all for the High initialization checks
        assert not {"missing-calls", "missing-init-modifier", "multiple-calls",
                    "variables-initialized"} & _keys(report, "v1")

    def test_initializable_pattern_checks_pass(self, report):
        assert not {"init-inherited", "init-missing", "initializer-missing"} & _keys(
            report, "v1"
        )

    def test_gap_observations(self, report):
        gaps = report.findings_for("v1", "gap-reserved")
        assert len(gaps) == 2  # OwnableUpgradeable + GoodImpl
        assert all(g.status == cu.INFO for g in gaps)
        assert any("49" in g.message for g in gaps)

    def test_no_destructive_patterns(self, report):
        assert not {"no-selfdestruct", "no-delegatecall"} & _keys(report, "v1")

    def test_render_has_skip_lines_for_unrequested_modes(self, report):
        text = cu.render(report)
        assert "[SKIP] became-constant" in text
        assert "[SKIP] order-vars-proxy" in text
        assert "[SKIP] function-id-collision" in text
        assert "RESULT: PASS" in text


class TestBrokenImpl:
    @pytest.fixture
    def report(self, session):
        return _review(session, "BrokenImpl")

    def test_fails(self, report):
        assert not report.ok
        assert report.failures == 2

    def test_missing_init_modifier(self, report):
        findings = report.findings_for("v1", "missing-init-modifier")
        assert len(findings) == 1
        assert findings[0].status == cu.FAIL
        assert "BrokenImpl.initialize()" in findings[0].message
        assert "initializer" in findings[0].message

    def test_variables_initialized(self, report):
        findings = report.findings_for("v1", "variables-initialized")
        assert len(findings) == 1
        assert findings[0].status == cu.FAIL
        assert "threshold" in findings[0].message

    def test_selfdestruct_observation(self, report):
        findings = report.findings_for("v1", "no-selfdestruct")
        assert len(findings) == 1
        assert findings[0].status == cu.WARN
        assert "kill" in findings[0].message

    def test_initializer_missing_info(self, report):
        findings = report.findings_for("v1", "initializer-missing")
        assert len(findings) == 1
        assert findings[0].status == cu.INFO

    def test_init_pattern_present(self, report):
        # Initializable exists in the codebase and is inherited
        assert not report.findings_for("v1", "init-missing")
        assert not report.findings_for("v1", "init-inherited")


# ---------------------------------------------------------------------------
# initializer chaining (checks 4 and 6)
# ---------------------------------------------------------------------------


class TestInitChain:
    def test_good_chain_passes(self, session):
        report = _review(session, "GoodChainImpl")
        assert report.ok
        assert not report.findings_for("v1", "missing-calls")
        assert not report.findings_for("v1", "multiple-calls")

    def test_missing_base_call(self, session):
        report = _review(session, "MissingCallsImpl")
        findings = report.findings_for("v1", "missing-calls")
        assert len(findings) == 1
        assert findings[0].status == cu.FAIL
        assert "ChainBaseB.initializeB()" in findings[0].message
        assert not report.ok

    def test_multiple_calls_direct(self, session):
        report = _review(session, "MultipleCallsImpl")
        findings = report.findings_for("v1", "multiple-calls")
        assert len(findings) == 1
        assert findings[0].status == cu.FAIL
        assert "ChainBaseA.initializeA()" in findings[0].message
        assert "2 times" in findings[0].message

    def test_multiple_calls_through_helper(self, session):
        report = _review(session, "MultipleCallsHelperImpl")
        findings = report.findings_for("v1", "multiple-calls")
        assert len(findings) == 1
        assert "ChainBaseA.initializeA()" in findings[0].message


# ---------------------------------------------------------------------------
# Initializable pattern informational checks (14, 15, 17)
# ---------------------------------------------------------------------------


class TestNoInitializable:
    @pytest.fixture
    def report(self, noinit_session):
        return _review(noinit_session, "NoInitPattern")

    def test_init_missing(self, report):
        findings = report.findings_for("v1", "init-missing")
        assert len(findings) == 1
        assert findings[0].status == cu.INFO

    def test_init_inherited(self, report):
        findings = report.findings_for("v1", "init-inherited")
        assert len(findings) == 1
        assert findings[0].status == cu.INFO

    def test_initializer_missing(self, report):
        assert report.findings_for("v1", "initializer-missing")

    def test_unguarded_initialize_fails(self, report):
        findings = report.findings_for("v1", "missing-init-modifier")
        assert len(findings) == 1
        assert findings[0].status == cu.FAIL
        assert not report.ok


# ---------------------------------------------------------------------------
# V2 mode: storage-layout compatibility
# ---------------------------------------------------------------------------


class TestCompatibleV2:
    @pytest.fixture
    def report(self, session):
        return _review(session, "VaultV1", v2="VaultV2")

    def test_layout_compatible(self, report):
        assert report.ok
        assert not report.findings_for("layout", "order-vars-contracts")
        assert not report.findings_for("layout", "became-constant")
        assert not report.findings_for("layout", "were-constant")
        assert not report.findings_for("layout", "missing-variables")

    def test_extra_vars_info(self, report):
        findings = report.findings_for("layout", "extra-vars-v2")
        assert len(findings) == 1
        assert findings[0].status == cu.INFO
        assert "withdrawalFee" in findings[0].message

    def test_gap_shrunk_consistently(self, report):
        findings = report.findings_for("layout", "gap-consistency")
        assert len(findings) == 1
        assert findings[0].status == cu.INFO
        assert "47" in findings[0].message and "46" in findings[0].message

    def test_v2_initialization_checks_run(self, report):
        # the V2 initialization section is populated
        targets = report.findings_for("v2", "initialize-target")
        assert len(targets) == 1
        assert "VaultV2.initialize(address)" in targets[0].message


class TestIncompatibleV2:
    def test_reorder(self, session):
        report = _review(session, "VaultV1", v2="VaultV2Reorder")
        findings = report.findings_for("layout", "order-vars-contracts")
        assert len(findings) == 1
        assert findings[0].status == cu.FAIL
        assert "position 1" in findings[0].message
        assert not report.ok

    def test_insert(self, session):
        report = _review(session, "VaultV1", v2="VaultV2Insert")
        findings = report.findings_for("layout", "order-vars-contracts")
        assert len(findings) == 1
        assert "withdrawalFee" in findings[0].message
        # the inserted variable is also reported as an extra var
        extras = report.findings_for("layout", "extra-vars-v2")
        assert any("withdrawalFee" in f.message for f in extras)

    def test_delete(self, session):
        report = _review(session, "VaultV1", v2="VaultV2Delete")
        assert report.findings_for("layout", "order-vars-contracts")
        missing = report.findings_for("layout", "missing-variables")
        assert len(missing) == 1
        assert missing[0].status == cu.WARN
        assert "totalDeposits" in missing[0].message

    def test_retype(self, session):
        report = _review(session, "VaultV1", v2="VaultV2Retype")
        findings = report.findings_for("layout", "order-vars-contracts")
        assert len(findings) == 1
        assert "uint256" in findings[0].message
        assert "uint128" in findings[0].message

    def test_became_constant(self, session):
        report = _review(session, "VaultV1", v2="VaultV2Const")
        findings = report.findings_for("layout", "became-constant")
        assert len(findings) == 1
        assert findings[0].status == cu.FAIL
        assert "totalDeposits" in findings[0].message

    def test_were_constant(self, session):
        report = _review(session, "VaultV1", v2="VaultV2Unconst")
        findings = report.findings_for("layout", "were-constant")
        assert len(findings) == 1
        assert findings[0].status == cu.FAIL
        assert "VERSION" in findings[0].message

    def test_gap_not_shrunk_warns_but_passes(self, session):
        report = _review(session, "VaultV1", v2="VaultV2BadGap")
        findings = report.findings_for("layout", "gap-consistency")
        assert len(findings) == 1
        assert findings[0].status == cu.WARN
        # warnings alone do not fail the run
        assert report.ok

    def test_v2_introduces_selfdestruct(self, session):
        report = _review(session, "VaultV1", v2="VaultV2Destructive")
        findings = report.findings_for("v2", "no-selfdestruct")
        assert len(findings) == 1
        assert findings[0].status == cu.WARN
        assert "newly introduced in V2" in findings[0].message


# ---------------------------------------------------------------------------
# proxy mode (checks 2, 3, 8, 11)
# ---------------------------------------------------------------------------


class TestProxyChecks:
    def test_function_shadowing(self, session):
        report = _review(session, "ProxyImpl", proxy="TokenProxy")
        findings = report.findings_for("proxy", "function-shadowing")
        messages = [f.message for f in findings]
        assert any("TokenProxy.admin()" in m for m in messages)
        assert any("TokenProxy.implementation()" in m for m in messages)
        assert all(f.status == cu.FAIL for f in findings)
        assert not report.ok

    def test_function_id_collision(self, session):
        report = _review(session, "ProxyImpl", proxy="TokenProxy")
        findings = report.findings_for("proxy", "function-id-collision")
        assert len(findings) == 1
        assert findings[0].status == cu.FAIL
        assert "0x42966c68" in findings[0].message
        assert "collate_propagate_storage(bytes16)" in findings[0].message
        assert "burn(uint256)" in findings[0].message

    def test_extra_vars_proxy(self, session):
        report = _review(session, "ProxyImpl", proxy="TokenProxy")
        findings = report.findings_for("proxy", "extra-vars-proxy")
        assert len(findings) == 1
        assert findings[0].status == cu.WARN
        assert "pendingAdmin" in findings[0].message

    def test_order_vars_proxy_ok(self, session):
        report = _review(session, "ProxyImpl", proxy="TokenProxy")
        assert not report.findings_for("proxy", "order-vars-proxy")

    def test_order_vars_proxy_mismatch(self, session):
        report = _review(session, "ProxyImpl", proxy="BadOrderProxy")
        findings = report.findings_for("proxy", "order-vars-proxy")
        assert len(findings) == 1
        assert findings[0].status == cu.FAIL
        assert "relative order" in findings[0].message
        assert not report.ok

    def test_clean_proxy_passes(self, session):
        report = _review(session, "ProxyImpl", proxy="CleanProxy")
        assert report.ok
        assert not _keys(report, "proxy")


# ---------------------------------------------------------------------------
# JSON output (§C.4.2)
# ---------------------------------------------------------------------------


class TestJsonOutput:
    def test_envelope_v1_mode(self, session):
        report = _review(session, "BrokenImpl")
        doc = cu.build_json_document(report)
        assert doc["success"] is True
        assert doc["error"] is None
        sub = doc["results"]["upgradeability-check"]
        assert set(sub) == {
            "check-initialization",
            "check-initialization-v2",
            "compare-function-ids",
            "compare-variables-order-proxy",
            "compare-variables-order-implementation",
        }
        # not requested -> documented empty objects
        assert sub["check-initialization-v2"] == {}
        assert sub["compare-function-ids"] == {}
        assert sub["compare-variables-order-proxy"] == {}
        assert sub["compare-variables-order-implementation"] == {}
        # requested -> finding lists
        init_checks = {f["check"] for f in sub["check-initialization"]}
        assert "missing-init-modifier" in init_checks
        assert "variables-initialized" in init_checks
        finding = next(
            f for f in sub["check-initialization"]
            if f["check"] == "missing-init-modifier"
        )
        assert finding["impact"] == "High"
        assert finding["confidence"] == "High"
        assert finding["elements"]
        assert finding["elements"][0]["type"] == "function"
        assert "source_mapping" in finding["elements"][0]

    def test_envelope_v2_and_proxy_modes(self, session):
        report = _review(session, "ProxyImpl", v2="VaultV2", proxy="TokenProxy")
        doc = cu.build_json_document(report)
        sub = doc["results"]["upgradeability-check"]
        assert isinstance(sub["check-initialization"], list)
        assert isinstance(sub["check-initialization-v2"], list)
        assert isinstance(sub["compare-function-ids"], list)
        assert isinstance(sub["compare-variables-order-proxy"], list)
        assert isinstance(sub["compare-variables-order-implementation"], list)
        id_checks = {f["check"] for f in sub["compare-function-ids"]}
        assert "function-id-collision" in id_checks
        assert "function-shadowing" in id_checks
        layout_checks = {f["check"] for f in sub["compare-variables-order-implementation"]}
        assert "extra-vars-v2" in layout_checks

    def test_json_serializable(self, session):
        report = _review(session, "VaultV1", v2="VaultV2Reorder")
        text = json.dumps(cu.build_json_document(report))
        assert "order-vars-contracts" in text


# ---------------------------------------------------------------------------
# CLI: exit codes, modes, --json
# ---------------------------------------------------------------------------


class TestCli:
    def test_good_impl_exit_0(self, capsys):
        code = cu.main([str(FIXTURES / "GoodImpl.sol"), "GoodImpl"])
        out = capsys.readouterr().out
        assert code == 0
        assert "# Check upgradeability: GoodImpl" in out
        assert "[PASS] missing-init-modifier" in out
        assert "RESULT: PASS" in out

    def test_broken_impl_exit_1(self, capsys):
        code = cu.main([str(FIXTURES / "BrokenImpl.sol"), "BrokenImpl"])
        out = capsys.readouterr().out
        assert code == 1
        assert "[FAIL] missing-init-modifier" in out
        assert "[FAIL] variables-initialized" in out
        assert "RESULT: FAIL" in out

    def test_v2_mode_same_target(self, capsys):
        code = cu.main([str(FIXTURES), "VaultV1", "VaultV2"])
        out = capsys.readouterr().out
        assert code == 0
        assert "# Check upgradeability: VaultV1 -> VaultV2" in out
        assert "## Storage layout — VaultV1 -> VaultV2" in out
        assert "[PASS] order-vars-contracts" in out
        assert "## Initialization checks — VaultV2 (V2)" in out

    def test_v2_mode_cross_file(self, capsys):
        code = cu.main(
            [
                str(FIXTURES / "VaultV1.sol"), "VaultV1", "VaultV2",
                "--new-contract-filename", str(FIXTURES / "VaultV2.sol"),
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "[PASS] order-vars-contracts" in out

    def test_incompatible_v2_exit_1(self, capsys):
        code = cu.main([str(FIXTURES), "VaultV1", "VaultV2Reorder"])
        assert code == 1
        assert "[FAIL] order-vars-contracts" in capsys.readouterr().out

    def test_proxy_mode(self, capsys):
        code = cu.main(
            [str(FIXTURES), "ProxyImpl", "--proxy-name", "TokenProxy"]
        )
        out = capsys.readouterr().out
        assert code == 1
        assert "## Proxy review — TokenProxy vs ProxyImpl" in out
        assert "[FAIL] function-shadowing" in out
        assert "[FAIL] function-id-collision" in out
        assert "[WARN] extra-vars-proxy" in out

    def test_proxy_mode_cross_file(self, capsys):
        code = cu.main(
            [
                str(FIXTURES / "ProxyImpl.sol"), "ProxyImpl",
                "--proxy-name", "CleanProxy",
                "--proxy-filename", str(FIXTURES / "CleanProxy.sol"),
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "[PASS] function-shadowing" in out

    def test_json_stdout(self, capsys):
        code = cu.main(
            [str(FIXTURES / "BrokenImpl.sol"), "BrokenImpl", "--json", "-"]
        )
        out = capsys.readouterr().out
        assert code == 1
        doc = json.loads(out)  # stdout carries only the JSON document
        assert doc["success"] is True
        sub = doc["results"]["upgradeability-check"]
        checks = {f["check"] for f in sub["check-initialization"]}
        assert "missing-init-modifier" in checks
        assert sub["compare-function-ids"] == {}

    def test_json_file(self, tmp_path, capsys):
        target = tmp_path / "report.json"
        code = cu.main(
            [str(FIXTURES / "GoodImpl.sol"), "GoodImpl", "--json", str(target)]
        )
        assert code == 0
        doc = json.loads(target.read_text())
        assert doc["success"] is True
        # console report still printed when JSON goes to a file
        assert "RESULT: PASS" in capsys.readouterr().out

    def test_unknown_contract_exit_2(self, capsys):
        code = cu.main([str(FIXTURES / "GoodImpl.sol"), "Nope"])
        assert code == 2
        assert "not found" in capsys.readouterr().err

    def test_unknown_v2_contract_exit_2(self, capsys):
        code = cu.main([str(FIXTURES), "VaultV1", "Nope"])
        assert code == 2

    def test_proxy_filename_without_name_exit_2(self, capsys):
        code = cu.main(
            [
                str(FIXTURES / "GoodImpl.sol"), "GoodImpl",
                "--proxy-filename", str(FIXTURES / "CleanProxy.sol"),
            ]
        )
        assert code == 2
        assert "--proxy-name" in capsys.readouterr().err

    def test_new_contract_filename_without_name_exit_2(self, capsys):
        code = cu.main(
            [
                str(FIXTURES / "VaultV1.sol"), "VaultV1",
                "--new-contract-filename", str(FIXTURES / "VaultV2.sol"),
            ]
        )
        assert code == 2
        assert "NEW_CONTRACT" in capsys.readouterr().err

    def test_json_error_envelope(self, capsys):
        code = cu.main(
            [str(FIXTURES / "GoodImpl.sol"), "Nope", "--json", "-"]
        )
        out = capsys.readouterr().out
        assert code == 2
        doc = json.loads(out)
        assert doc["success"] is False
        assert "not found" in doc["error"]


class TestConsoleScript:
    def test_module_invocation(self):
        result = subprocess.run(
            [
                sys.executable, "-m", "velvet.tools.check_upgradeability",
                str(FIXTURES / "GoodImpl.sol"), "GoodImpl",
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "RESULT: PASS" in result.stdout

    def test_module_invocation_failing(self):
        result = subprocess.run(
            [
                sys.executable, "-m", "velvet.tools.check_upgradeability",
                str(FIXTURES / "BrokenImpl.sol"), "BrokenImpl",
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        assert "RESULT: FAIL" in result.stdout
