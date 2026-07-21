"""Output/reporting modes, wave 2 (spec/architecture.md §10.3-10.5,
spec/api-surface.md §7.2, spec/printers-and-tools.md §C.3-C.4):

- ``--generate-patches`` / ``--patches-dir`` — machine-applicable patches
  (JSON ``patches`` objects + unified-diff files) for the five patchable
  detectors: ``solc-version``, ``pragma``, ``constable-states``,
  ``immutable-states``, ``naming-convention``;
- ``--wiki DIR`` — per-detector documentation pages + impact-grouped index;
- ``--zip FILE`` / ``--zip-type`` — compressed results bundle;
- ``--sarif-input`` / ``--sarif-triage`` — SARIF triage import/export.

Original clean-room implementation.
"""

from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

import pytest

import velvet.cli
from velvet.cli import build_parser, main
from velvet.detectors import BUILTIN_DETECTORS
from velvet.outputs.json_out import build_json_output
from velvet.outputs.patches import (
    PATCH_FORMAT,
    PatchEdit,
    apply_edits_to_source,
    convert_identifier,
    finding_patches_dict,
    patches_for_finding,
    patch_provider_for,
)
from velvet.outputs.sarif import build_sarif
from velvet.outputs.wiki import INDEX_PAGE, render_index, write_wiki
from velvet.outputs.zip_export import (
    CONSOLE_MEMBER,
    RESULTS_MEMBER,
    ZIP_TYPES,
    write_zip_export,
)
from velvet.session import Velvet
from velvet.triage import TriageDatabase, import_sarif_triage

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "detectors"
SOLC_VERSION = FIXTURES / "SolcVersion.sol"
PRAGMA_PROJECT = FIXTURES / "pragma"
CONSTABLE = FIXTURES / "constable-states" / "ConstableStates.sol"
IMMUTABLE = FIXTURES / "immutable-states" / "ImmutableStates.sol"
NAMING = FIXTURES / "naming-convention" / "NamingConvention.sol"
TX_ORIGIN = FIXTURES / "TxOrigin.sol"


# --------------------------------------------------------------- sessions
@pytest.fixture(scope="module")
def solc_version_session() -> Velvet:
    return Velvet(str(SOLC_VERSION), disable_color=True, generate_patches=True)


@pytest.fixture(scope="module")
def pragma_session() -> Velvet:
    return Velvet(str(PRAGMA_PROJECT), disable_color=True, generate_patches=True)


@pytest.fixture(scope="module")
def constable_session() -> Velvet:
    return Velvet(str(CONSTABLE), disable_color=True, generate_patches=True)


@pytest.fixture(scope="module")
def immutable_session() -> Velvet:
    return Velvet(str(IMMUTABLE), disable_color=True, generate_patches=True)


@pytest.fixture(scope="module")
def naming_session() -> Velvet:
    return Velvet(str(NAMING), disable_color=True, generate_patches=True)


@pytest.fixture(scope="module")
def tx_origin_session(tmp_path_factory) -> Velvet:
    db = tmp_path_factory.mktemp("o2-shared") / "absent.db.json"
    return Velvet(str(TX_ORIGIN), disable_color=True, triage_database=str(db))


# ---------------------------------------------------------------- helpers
def _json_findings(session: Velvet, check: str) -> list[dict]:
    """JSON finding dicts for one rule (with patches attached)."""
    findings = [f for f in session.run_detectors() if f.check == check]
    document = build_json_output(session, findings)
    return document["results"]["detectors"]


def _apply_json_edits(edits: list[dict]) -> dict[str, str]:
    """Apply JSON patch edits to the on-disk sources; returns
    ``{filename_absolute: patched text}`` (mission: apply the patch text to
    the source at the offset)."""
    by_file: dict[str, list[dict]] = {}
    for edit in edits:
        by_file.setdefault(edit["filename_absolute"], []).append(edit)
    patched: dict[str, str] = {}
    for path, file_edits in by_file.items():
        source = Path(path).read_text()
        for edit in sorted(file_edits, key=lambda e: e["start"], reverse=True):
            start, length = edit["start"], edit["length"]
            source = source[:start] + edit["replacement"] + source[start + length :]
        patched[path] = source
    return patched


def _recompile(source: str, tmp_path: Path, name: str, check: str) -> list:
    """Write patched source, compile it fresh, return findings for `check`."""
    target = tmp_path / name
    target.write_text(source)
    session = Velvet(str(target), disable_color=True)
    return [f for f in session.run_detectors() if f.check == check]


def _patch_edit(json_finding: dict) -> dict:
    assert "patches" in json_finding, f"no patches on {json_finding['check']}"
    assert json_finding["patches"]["format"] == PATCH_FORMAT
    edits = json_finding["patches"]["edits"]
    assert len(edits) == 1
    return edits[0]


# ================================================================= patches
class TestPatchFramework:
    def test_registry_wires_the_five_patchable_detectors(self):
        for rule in (
            "solc-version",
            "pragma",
            "constable-states",
            "immutable-states",
            "naming-convention",
        ):
            assert patch_provider_for(rule) is not None
        assert patch_provider_for("tx-origin") is None

    def test_apply_edits_to_source_splices_and_inserts(self):
        source = "uint256 public maxFeeBps = 500"
        insertion = PatchEdit("f.sol", "f.sol", "/f.sol", 15, 0, "constant ")
        assert apply_edits_to_source(source, [insertion]) == (
            "uint256 public constant maxFeeBps = 500"
        )
        replacement = PatchEdit("f.sol", "f.sol", "/f.sol", 15, 9, "minFee")
        assert apply_edits_to_source(source, [replacement]) == (
            "uint256 public minFee = 500"
        )

    def test_apply_edits_rejects_overlaps(self):
        edits = [
            PatchEdit("f", "f", "/f", 2, 4, "aa"),
            PatchEdit("f", "f", "/f", 4, 2, "bb"),
        ]
        with pytest.raises(ValueError, match="overlapping"):
            apply_edits_to_source("0123456789", edits)

    def test_convert_identifier(self):
        assert convert_identifier("my_token", "CapWords") == "MyToken"
        assert convert_identifier("transferred", "CapWords") == "Transferred"
        assert convert_identifier("TOTAL", "mixedCase") == "total"
        assert convert_identifier("TransferCoins", "mixedCase") == "transferCoins"
        assert convert_identifier("BAD_local", "mixedCase") == "badLocal"
        assert convert_identifier("maxSupply", "UPPER_CASE_WITH_UNDERSCORES") == (
            "MAX_SUPPLY"
        )
        assert convert_identifier("_private", "mixedCase") == "_private"


class TestSolcVersionPatch:
    def test_json_patch_replaces_pragma_range(self, solc_version_session, tmp_path):
        findings = _json_findings(solc_version_session, "solc-version")
        assert len(findings) == 1
        edit = _patch_edit(findings[0])
        assert edit["replacement"] == "0.8.24"
        patched = _apply_json_edits([edit])[edit["filename_absolute"]]
        assert "pragma solidity 0.8.24;" in patched
        # patched result compiles and the finding is gone
        assert _recompile(patched, tmp_path, "SolcVersion.sol", "solc-version") == []

    def test_patch_offsets_match_source_text(self, solc_version_session):
        finding = [f for f in solc_version_session.run_detectors() if f.check == "solc-version"][0]
        (edit,) = patches_for_finding(finding, solc_version_session)
        source = Path(edit.filename_absolute).read_text()
        assert source[edit.start : edit.start + edit.length] == ">=0.4.22 <0.9.0"


class TestPragmaPatch:
    def test_json_patch_unifies_to_anchor_version(self, pragma_session, tmp_path):
        findings = _json_findings(pragma_session, "pragma")
        assert len(findings) == 1
        edit = _patch_edit(findings[0])
        assert edit["replacement"] == "^0.8.0"
        assert edit["filename"].endswith("TokenB.sol")
        patched = _apply_json_edits([edit])[edit["filename_absolute"]]
        assert "pragma solidity ^0.8.0;" in patched
        # copy the project with the patched file: versions unify -> no finding
        shutil.copy(PRAGMA_PROJECT / "TokenA.sol", tmp_path / "TokenA.sol")
        assert _recompile(patched, tmp_path, "TokenB.sol", "pragma") == []


@pytest.fixture(scope="module")
def pragma_multi_session() -> Velvet:
    project = FIXTURES / "pragma-multi"
    return Velvet(str(project), disable_color=True, generate_patches=True)


class TestPragmaSingleFindingPerUnit:
    """One finding per compilation unit with mixed pragma expressions."""

    def test_single_finding_lists_all_conflicting_directives(self, pragma_multi_session):
        findings = _json_findings(pragma_multi_session, "pragma")
        assert len(findings) == 1
        desc = findings[0]["description"]
        # anchor ^0.8.0 plus two conflicting expressions, one finding
        assert ">=0.7.0<0.9.0" in desc and ">=0.6.0<0.9.0" in desc

    def test_patch_unifies_every_conflicting_directive(self, pragma_multi_session):
        findings = _json_findings(pragma_multi_session, "pragma")
        assert len(findings) == 1
        edits = findings[0]["patches"]["edits"]
        targets = {e["filename"].rsplit("/", 1)[-1] for e in edits}
        assert targets == {"TokenB.sol", "TokenD.sol"}
        assert all(e["replacement"] == "^0.8.0" for e in edits)


class TestConstableStatesPatch:
    def test_json_patches_insert_constant(self, constable_session, tmp_path):
        findings = _json_findings(constable_session, "constable-states")
        assert len(findings) == 2
        edits = [_patch_edit(f) for f in findings]
        assert all(e["replacement"] == "constant " for e in edits)
        assert all(e["length"] == 0 for e in edits)  # pure insertion
        patched = _apply_json_edits(edits)[edits[0]["filename_absolute"]]
        assert "uint256 public constant maxFeeBps = 500;" in patched
        assert 'string public constant version = "1.0";' in patched
        # patched result compiles and both findings are gone
        assert _recompile(patched, tmp_path, "ConstableStates.sol", "constable-states") == []


class TestImmutableStatesPatch:
    def test_json_patches_insert_immutable(self, immutable_session, tmp_path):
        findings = _json_findings(immutable_session, "immutable-states")
        assert len(findings) == 3
        edits = [_patch_edit(f) for f in findings]
        assert all(e["replacement"] == "immutable " for e in edits)
        patched = _apply_json_edits(edits)[edits[0]["filename_absolute"]]
        assert "address public immutable owner;" in patched
        assert "uint256 public immutable created;" in patched
        assert "uint256 public immutable deployedAt = block.timestamp;" in patched
        assert _recompile(patched, tmp_path, "ImmutableStates.sol", "immutable-states") == []


class TestNamingConventionPatch:
    #: old name -> convention-conformant replacement (all fixture findings)
    EXPECTED = {
        "my_token": "MyToken",
        "TOTAL": "total",
        "maxSupply": "MAX_SUPPLY",
        "transferred": "Transferred",
        "order": "Order",
        "status": "Status",
        "TransferCoins": "transferCoins",
        "To": "to",
        "RET": "ret",
        "BAD_local": "badLocal",
        "OnlyAdmin": "onlyAdmin",
    }

    def test_json_patches_rename_declarations(self, naming_session):
        findings = _json_findings(naming_session, "naming-convention")
        assert len(findings) == len(self.EXPECTED)
        source = Path(str(NAMING)).read_text()
        seen: dict[str, str] = {}
        for finding in findings:
            edit = _patch_edit(finding)
            old = source[edit["start"] : edit["start"] + edit["length"]]
            seen[old] = edit["replacement"]
            assert edit["replacement"] == self.EXPECTED[old]
            # the declaration site alone is rewritten to the expected text
            patched = _apply_json_edits([edit])[edit["filename_absolute"]]
            assert patched != source
        assert seen == self.EXPECTED

    def test_applied_subset_compiles(self, naming_session, tmp_path):
        # Skip the two fixture-unsafe renames: BAD_local is referenced by a
        # `return` (declaration-only rename would dangle) and my_token would
        # collide with the fixture's safe `MyToken` contract.
        skip = {"BAD_local", "my_token"}
        edits = []
        for finding in naming_session.run_detectors():
            if finding.check != "naming-convention":
                continue
            if getattr(finding.primary_element, "name", "") in skip:
                continue
            edits.extend(patches_for_finding(finding, naming_session))
        patched = apply_edits_to_source(Path(str(NAMING)).read_text(), edits)
        remaining = _recompile(patched, tmp_path, "NamingConvention.sol", "naming-convention")
        assert {getattr(f.primary_element, "name", "") for f in remaining} <= skip


class TestPatchGating:
    def test_non_patchable_findings_have_no_patches_key(self, tx_origin_session):
        session = tx_origin_session
        session.generate_patches = True
        try:
            findings = [f for f in session.run_detectors() if f.check == "tx-origin"]
            assert findings
            document = build_json_output(session, findings)
            for item in document["results"]["detectors"]:
                assert "patches" not in item
        finally:
            session.generate_patches = False  # restore the shared session

    def test_patches_omitted_without_the_flag(self, constable_session):
        constable_session.generate_patches = False
        try:
            findings = [f for f in constable_session.run_detectors() if f.check == "constable-states"]
            document = build_json_output(constable_session, findings)
            assert findings
            for item in document["results"]["detectors"]:
                assert "patches" not in item
        finally:
            constable_session.generate_patches = True  # restore shared session

    def test_provider_returns_nothing_for_unknown_source(self):
        from velvet.detectors.base import Confidence, Finding, Impact

        finding = Finding(
            elements=["just text"],
            check="constable-states",
            impact=Impact.OPTIMIZATION,
            confidence=Confidence.HIGH,
        )
        assert patches_for_finding(finding, session=None) == []
        assert finding_patches_dict(finding, session=None) is None


class TestPatchesCli:
    def test_generate_patches_json_stdout(self, capsys):
        code = main([str(SOLC_VERSION), "--detect", "solc-version", "--generate-patches", "--json", "-"])
        assert code == 0
        document = json.loads(capsys.readouterr().out)
        patches = document["results"]["detectors"][0]["patches"]
        assert patches["format"] == PATCH_FORMAT
        assert patches["edits"][0]["replacement"] == "0.8.24"

    def test_patches_dir_writes_unified_diffs(self, tmp_path, capsys):
        patches_dir = tmp_path / "patches"
        json_target = tmp_path / "out.json"
        code = main(
            [
                str(CONSTABLE),
                "--detect",
                "constable-states",
                "--patches-dir",
                str(patches_dir),
                "--json",
                str(json_target),
            ]
        )
        assert code == 0
        capsys.readouterr()
        files = sorted(patches_dir.glob("*.patch"))
        assert len(files) == 2
        content = files[0].read_text()
        assert content.startswith("--- a/ConstableStates.sol")
        assert "+++ b/ConstableStates.sol" in content
        assert "+    uint256 public constant maxFeeBps = 500;" in content
        # --patches-dir implies --generate-patches in the JSON output
        document = json.loads(json_target.read_text())
        assert "patches" in document["results"]["detectors"][0]


# ==================================================================== wiki
class TestWiki:
    def test_pages_for_all_registered_detectors(self, tmp_path):
        written = write_wiki(list(BUILTIN_DETECTORS), tmp_path)
        assert len(written) == len(BUILTIN_DETECTORS) + 1  # pages + index
        pages = {p.name for p in tmp_path.glob("*.md")}
        assert INDEX_PAGE in pages
        for detector_class in BUILTIN_DETECTORS:
            assert f"{detector_class.RULE}.md" in pages

    def test_page_content_from_docs_block(self, tmp_path):
        write_wiki(list(BUILTIN_DETECTORS), tmp_path)
        page = (tmp_path / "solc-version.md").read_text()
        assert page.startswith("# Outdated or complex solc version pragma\n")
        assert "| **Rule** | `solc-version` |" in page
        assert "| **Impact** | Informational |" in page
        assert "| **Confidence** | High |" in page
        assert "## Description" in page
        assert "## Exploit scenario" in page
        assert "## Recommendation" in page
        assert "0.8.24" in page

    def test_index_grouped_by_impact(self, tmp_path):
        index = render_index(list(BUILTIN_DETECTORS))
        (tmp_path / INDEX_PAGE).write_text(index)
        for impact in ("High", "Medium", "Low", "Informational", "Optimization"):
            assert f"## {impact}" in index
        assert "| # | Check | Title | Confidence |" in index
        assert "[solc-version](solc-version.md)" in index
        assert "[tx-origin](tx-origin.md)" in index
        assert f"{len(BUILTIN_DETECTORS)} detectors documented." in index
        # continuous numbering across the impact groups, 0 .. N-1
        numbers = [
            int(line.split("|")[1].strip())
            for line in index.splitlines()
            if line.startswith("| ") and line.split("|")[1].strip().isdigit()
        ]
        assert numbers == list(range(len(BUILTIN_DETECTORS)))
        # groups are really impact-ordered (High first, Optimization last)
        assert index.index("## High") < index.index("## Medium") < index.index(
            "## Informational"
        ) < index.index("## Optimization")

    def test_cli_wiki_without_target(self, tmp_path, capsys):
        assert main(["--wiki", str(tmp_path / "wiki")]) == 0
        assert "detector documentation" in capsys.readouterr().out
        assert (tmp_path / "wiki" / INDEX_PAGE).is_file()
        assert (tmp_path / "wiki" / "solc-version.md").is_file()

    def test_cli_wiki_alongside_analysis(self, tmp_path):
        wiki_dir = tmp_path / "wiki"
        code = main([str(TX_ORIGIN), "--disable-color", "--wiki", str(wiki_dir)])
        assert code == 0
        assert (wiki_dir / INDEX_PAGE).is_file()
        assert (wiki_dir / "tx-origin.md").is_file()


# ===================================================================== zip
class TestZipExport:
    @pytest.mark.parametrize("zip_type", ["lzma", "zlib", "stored"])
    def test_members_and_compression_types(self, tx_origin_session, tmp_path, zip_type):
        findings = tx_origin_session.run_detectors()
        target = tmp_path / f"bundle-{zip_type}.zip"
        write_zip_export(
            tx_origin_session,
            findings,
            target,
            zip_type=zip_type,
            console_text="console text",
        )
        with zipfile.ZipFile(target) as archive:
            assert archive.namelist() == [RESULTS_MEMBER, CONSOLE_MEMBER]
            for info in archive.infolist():
                assert info.compress_type == ZIP_TYPES[zip_type]
            document = json.loads(archive.read(RESULTS_MEMBER))
            assert document["success"] is True
            assert sorted(document["results"]) == ["compilations", "console", "detectors"]
            assert document["results"]["detectors"]
            assert archive.read(CONSOLE_MEMBER).decode() == "console text"

    def test_printers_section_only_when_printers_ran(self, tx_origin_session, tmp_path):
        target = tmp_path / "printers.zip"
        write_zip_export(
            tx_origin_session,
            [],
            target,
            printer_results=["printer output"],
        )
        with zipfile.ZipFile(target) as archive:
            document = json.loads(archive.read(RESULTS_MEMBER))
        assert document["results"]["printers"] == ["printer output"]

    def test_unknown_zip_type_rejected(self, tx_origin_session, tmp_path):
        with pytest.raises(ValueError, match="zip-type"):
            write_zip_export(tx_origin_session, [], tmp_path / "x.zip", zip_type="brotli")

    def test_cli_zip_default_lzma(self, tx_origin_session, tmp_path):
        target = tmp_path / "cli.zip"
        code = main([str(TX_ORIGIN), "--disable-color", "--zip", str(target)])
        assert code == 0
        with zipfile.ZipFile(target) as archive:
            assert archive.infolist()[0].compress_type == zipfile.ZIP_LZMA
            assert archive.namelist() == [RESULTS_MEMBER, CONSOLE_MEMBER]

    def test_cli_zip_type_zlib(self, tmp_path):
        target = tmp_path / "cli-zlib.zip"
        code = main(
            [str(TX_ORIGIN), "--disable-color", "--zip", str(target), "--zip-type", "zlib"]
        )
        assert code == 0
        with zipfile.ZipFile(target) as archive:
            assert archive.infolist()[0].compress_type == zipfile.ZIP_DEFLATED


# ============================================================= SARIF triage
def _triage_sarif_document(session: Velvet, tmp_path: Path) -> tuple[Path, list[str]]:
    """Export a triage SARIF for TxOrigin; returns (path, finding ids)."""
    findings = session.run_detectors()
    document = build_sarif(session, findings, triage=True)
    path = tmp_path / "export.sarif"
    path.write_text(json.dumps(document))
    ids = [f.id for f in findings]
    return path, ids


class TestSarifTriageImport:
    def test_import_hides_suppressed_findings(self, tx_origin_session, tmp_path):
        path, ids = _triage_sarif_document(tx_origin_session, tmp_path)
        document = json.loads(path.read_text())
        # a SARIF explorer marks the first result as suppressed/baselined
        result = document["runs"][0]["results"][0]
        result["suppressions"] = [{"kind": "external", "justification": "fp"}]
        result["baselineState"] = "unchanged"
        path.write_text(json.dumps(document))

        database = TriageDatabase(tmp_path / "db.json")
        assert import_sarif_triage(database, path) == 1
        assert database.is_hidden(ids[0])
        assert not database.is_hidden(ids[1])

        # and the session pipeline hides the finding on the next run
        session = Velvet(
            str(TX_ORIGIN),
            disable_color=True,
            sarif_input=str(path),
            triage_database=str(tmp_path / "db.json"),
        )
        visible = {f.id for f in session.run_detectors()}
        assert ids[0] not in visible
        assert ids[1] in visible

    def test_import_baseline_state_only(self, tx_origin_session, tmp_path):
        path, ids = _triage_sarif_document(tx_origin_session, tmp_path)
        document = json.loads(path.read_text())
        results = document["runs"][0]["results"]
        results[1]["baselineState"] = "updated"  # baselined, not suppressed
        path.write_text(json.dumps(document))
        database = TriageDatabase(tmp_path / "db.json")
        assert import_sarif_triage(database, path) == 1
        assert not database.is_hidden(ids[0])
        assert database.is_hidden(ids[1])

    def test_import_corrupt_or_missing_is_noop(self, tmp_path):
        bad = tmp_path / "bad.sarif"
        bad.write_text("{ nope !")
        database = TriageDatabase(tmp_path / "db.json")
        assert import_sarif_triage(database, bad) == 0
        assert import_sarif_triage(database, tmp_path / "absent.sarif") == 0
        assert database.hidden_ids == set()

    def test_import_persists_database(self, tx_origin_session, tmp_path):
        path, ids = _triage_sarif_document(tx_origin_session, tmp_path)
        document = json.loads(path.read_text())
        results = document["runs"][0]["results"]
        for result in results:
            result["suppressions"] = [{"kind": "external"}]
        path.write_text(json.dumps(document))
        db_path = tmp_path / "db.json"
        session = Velvet(
            str(TX_ORIGIN),
            disable_color=True,
            sarif_input=str(path),
            triage_database=str(db_path),
        )
        assert session.run_detectors() == []
        persisted = TriageDatabase.load(db_path)
        assert persisted.hidden_ids >= set(ids)


class TestSarifTriageExport:
    def test_export_marks_suppressions(self, tmp_path):
        db_path = tmp_path / "db.json"
        session = Velvet(
            str(TX_ORIGIN), disable_color=True, triage_database=str(db_path)
        )
        findings = session.run_detectors()
        database = TriageDatabase(db_path)
        database.hide([findings[0]])
        database.save()

        session.show_ignored_findings = True
        marked = session.run_detectors()
        document = build_sarif(session, marked, triage=True)
        results = document["runs"][0]["results"]
        hidden = [r for r in results if r.get("suppressions")]
        visible = [r for r in results if not r.get("suppressions")]
        assert len(hidden) == 1
        assert hidden[0]["suppressions"][0]["kind"] == "external"
        assert hidden[0]["baselineState"] == "unchanged"
        assert len(visible) == len(marked) - 1
        assert all(r["baselineState"] == "new" for r in visible)

    def test_plain_sarif_has_no_triage_state(self, tx_origin_session):
        findings = tx_origin_session.run_detectors()
        document = build_sarif(tx_origin_session, findings)
        for result in document["runs"][0]["results"]:
            assert "suppressions" not in result
            assert "baselineState" not in result

    def test_cli_round_trip(self, tmp_path, capsys):
        triage_sarif = tmp_path / "triage.sarif"
        db_path = tmp_path / "db.json"
        base = [str(TX_ORIGIN), "--disable-color", "--triage-database", str(db_path)]
        # 1. export the triage SARIF: everything visible, marked as new
        assert main(base + ["--sarif-triage", str(triage_sarif)]) == 0
        document = json.loads(triage_sarif.read_text())
        results = document["runs"][0]["results"]
        assert len(results) >= 2
        assert {r["baselineState"] for r in results} == {"new"}
        # 2. an explorer suppresses one result
        results[0]["suppressions"] = [{"kind": "external", "justification": "fp"}]
        results[0]["baselineState"] = "unchanged"
        triage_sarif.write_text(json.dumps(document))
        capsys.readouterr()
        # 3. importing hides it; re-exporting reports the suppression
        assert main(base + ["--sarif-input", str(triage_sarif)]) == 0
        capsys.readouterr()  # drain the import run's console output
        assert main(base + ["--sarif-triage", str(triage_sarif), "--json", "-"]) == 0
        out = capsys.readouterr().out
        visible = json.loads(out)["results"]["detectors"]
        assert len(visible) == len(results) - 1
        reexported = json.loads(triage_sarif.read_text())["runs"][0]["results"]
        suppressed = [r for r in reexported if r.get("suppressions")]
        assert len(suppressed) == 1
        assert suppressed[0]["baselineState"] == "unchanged"


# ============================================================= CLI surface
class TestCliFlags:
    def test_new_flags_parse(self):
        args = build_parser().parse_args(
            [
                "target.sol",
                "--generate-patches",
                "--patches-dir",
                "patches/",
                "--wiki",
                "wiki/",
                "--zip",
                "out.zip",
                "--zip-type",
                "zlib",
                "--sarif-input",
                "in.sarif",
                "--sarif-triage",
                "triage.sarif",
            ]
        )
        assert args.generate_patches is True
        assert args.patches_dir == "patches/"
        assert args.wiki == "wiki/"
        assert args.zip_file == "out.zip"
        assert args.zip_type == "zlib"
        assert args.sarif_input == "in.sarif"
        assert args.sarif_triage == "triage.sarif"

    def test_zip_type_choices_enforced(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["t.sol", "--zip-type", "brotli"])

    def test_config_keys_and_cli_precedence(self, tmp_path, monkeypatch, capsys):
        sarif_in = tmp_path / "in.sarif"
        sarif_in.write_text(json.dumps({"version": "2.1.0", "runs": []}))
        config = {
            "generate_patches": True,
            "sarif_input": str(sarif_in),
            "zip": str(tmp_path / "cfg.zip"),
            "zip_type": "stored",
            "wiki": str(tmp_path / "cfg-wiki"),
        }
        (tmp_path / "velvet.config.json").write_text(json.dumps(config))
        monkeypatch.chdir(tmp_path)

        captured: dict = {}
        real_velvet = velvet.cli.Velvet

        def spy(target, **options):
            captured.update(options)
            return real_velvet(target, **options)

        monkeypatch.setattr(velvet.cli, "Velvet", spy)
        assert main([str(SOLC_VERSION), "--detect", "solc-version", "--disable-color"]) == 0
        # config keys flowed into the session / outputs
        assert captured["generate_patches"] is True
        assert captured["sarif_input"] == str(sarif_in)
        assert (tmp_path / "cfg.zip").is_file()
        with zipfile.ZipFile(tmp_path / "cfg.zip") as archive:
            assert archive.infolist()[0].compress_type == zipfile.ZIP_STORED
        assert (tmp_path / "cfg-wiki" / INDEX_PAGE).is_file()

        # CLI wins over config
        captured.clear()
        cli_zip = tmp_path / "cli.zip"
        assert main(
            [
                str(SOLC_VERSION),
                "--detect",
                "solc-version",
                "--disable-color",
                "--zip",
                str(cli_zip),
                "--zip-type",
                "zlib",
            ]
        ) == 0
        assert cli_zip.is_file()
        with zipfile.ZipFile(cli_zip) as archive:
            assert archive.infolist()[0].compress_type == zipfile.ZIP_DEFLATED
