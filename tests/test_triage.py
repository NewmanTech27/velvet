"""Triage mode/database and markdown checklist tests
(spec/architecture.md §10.4 + §11; spec/printers-and-tools.md §C.4.4/C.6;
spec/api-surface.md §7.2/7.3).

Original clean-room implementation.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import velvet.cli
from velvet.cli import build_parser, main
from velvet.detectors.base import Confidence, Finding, Impact
from velvet.exceptions import VelvetError
from velvet.outputs.checklist import normalize_markdown_root, render_checklist
from velvet.session import Velvet
from velvet.triage import PROMPT, TriageDatabase, apply_triage

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
TX_ORIGIN = str(FIXTURES / "detectors" / "TxOrigin.sol")


class _FakeStdin(io.StringIO):
    """In-memory stdin that pretends to be a TTY for triage prompts."""

    def isatty(self) -> bool:
        return True


def _toy_finding(check: str = "toy", text: str = "issue") -> Finding:
    return Finding(
        elements=[text],
        check=check,
        impact=Impact.LOW,
        confidence=Confidence.HIGH,
    )


def _fake_session(db_path: Path, **overrides) -> SimpleNamespace:
    """Minimal session stand-in for pure (compile-free) apply_triage tests."""
    options = {
        "triage_database": str(db_path),
        "triage_mode": False,
        "show_ignored_findings": False,
        "disable_color": True,
        "change_line_prefix": "#",
    }
    options.update(overrides)
    return SimpleNamespace(**options)


@pytest.fixture(scope="module")
def session(tmp_path_factory) -> Velvet:
    """One compiled TxOrigin session; db path deliberately absent."""
    db = tmp_path_factory.mktemp("triage-shared") / "absent.db.json"
    return Velvet(TX_ORIGIN, disable_color=True, triage_database=str(db))


# ---------------------------------------------------------------- database
class TestTriageDatabase:
    def test_roundtrip(self, tmp_path):
        path = tmp_path / "velvet.db.json"
        finding = _toy_finding(check="reentrancy", text="bad call")
        database = TriageDatabase(path)
        database.hide([finding])
        database.save()

        loaded = TriageDatabase.load(path)
        assert loaded.is_hidden(finding.id)
        assert not loaded.is_hidden("0" * 64)
        record = loaded.entries[finding.id]
        assert record["check"] == "reentrancy"
        assert record["impact"] == "Low"
        assert record["description"] == "bad call"
        # documented envelope
        assert json.loads(path.read_text())["version"] == 1

    def test_missing_file_is_empty(self, tmp_path):
        assert TriageDatabase.load(tmp_path / "nope.db.json").hidden_ids == set()

    def test_corrupt_file_is_empty(self, tmp_path):
        path = tmp_path / "velvet.db.json"
        path.write_text("{ not json !")
        assert TriageDatabase.load(path).hidden_ids == set()

    def test_list_form_tolerated(self, tmp_path):
        path = tmp_path / "velvet.db.json"
        path.write_text(json.dumps({"hidden": ["abc", "def"]}))
        loaded = TriageDatabase.load(path)
        assert loaded.hidden_ids == {"abc", "def"}


# ------------------------------------------------------- pipeline (pure)
class TestApplyTriage:
    def test_hides_recorded_findings(self, tmp_path):
        keep, drop = _toy_finding(text="keep"), _toy_finding(text="drop")
        db_path = tmp_path / "db.json"
        database = TriageDatabase(db_path)
        database.hide([drop])
        database.save()

        session = _fake_session(db_path)
        visible = apply_triage(session, [keep, drop])
        assert visible == [keep]

    def test_show_ignored_findings_marks_hidden(self, tmp_path):
        keep, drop = _toy_finding(text="keep"), _toy_finding(text="drop")
        db_path = tmp_path / "db.json"
        database = TriageDatabase(db_path)
        database.hide([drop])
        database.save()

        session = _fake_session(db_path, show_ignored_findings=True)
        visible = apply_triage(session, [keep, drop])
        assert visible == [keep, drop]
        assert getattr(drop, "hidden") is True
        assert getattr(keep, "hidden", False) is False

    def test_unknown_and_stale_ids_ignored(self, tmp_path):
        findings = [_toy_finding(text="a"), _toy_finding(text="b")]
        db_path = tmp_path / "db.json"
        db_path.write_text(
            json.dumps({"version": 1, "hidden": {"f" * 64: {"check": "toy"}}})
        )
        session = _fake_session(db_path)
        assert apply_triage(session, findings) == findings
        assert all(getattr(f, "hidden", False) is False for f in findings)

    def test_no_database_no_changes(self, tmp_path):
        findings = [_toy_finding(text="a")]
        session = _fake_session(tmp_path / "absent.db.json")
        assert apply_triage(session, findings) == findings


# ------------------------------------------------- interactive triage mode
class TestInteractiveTriage:
    def test_hide_persists_across_sessions(self, tmp_path, monkeypatch, capsys):
        db_path = tmp_path / "velvet.db.json"
        session = Velvet(TX_ORIGIN, disable_color=True, triage_database=str(db_path))
        all_ids = {f.id for f in session.run_detectors()}

        # interactive run: hide finding 0
        monkeypatch.setattr(sys, "stdin", _FakeStdin("0\n"))
        session.triage_mode = True
        survivors = session.run_detectors()
        out = capsys.readouterr().out
        assert "[0]" in out and PROMPT.split(":")[0] in out
        hidden_ids = all_ids - {f.id for f in survivors}
        assert len(hidden_ids) == 1
        assert TriageDatabase.load(db_path).hidden_ids == hidden_ids

        # subsequent run (no --triage-mode) hides it automatically
        session.triage_mode = False
        assert {f.id for f in session.run_detectors()} == all_ids - hidden_ids

        # --show-ignored-findings reveals it, marked as hidden
        session.show_ignored_findings = True
        revealed = session.run_detectors()
        assert {f.id for f in revealed} == all_ids
        marked = [f for f in revealed if getattr(f, "hidden", False)]
        assert {f.id for f in marked} == hidden_ids

    def test_hide_all(self, tmp_path, monkeypatch):
        db_path = tmp_path / "velvet.db.json"
        session = Velvet(TX_ORIGIN, disable_color=True, triage_database=str(db_path))
        monkeypatch.setattr(sys, "stdin", _FakeStdin("All\n"))
        session.triage_mode = True
        assert session.run_detectors() == []
        session.triage_mode = False
        assert session.run_detectors() == []  # persists without triage mode

    def test_enter_hides_nothing(self, tmp_path, monkeypatch):
        db_path = tmp_path / "velvet.db.json"
        session = Velvet(TX_ORIGIN, disable_color=True, triage_database=str(db_path))
        monkeypatch.setattr(sys, "stdin", _FakeStdin("\n"))
        session.triage_mode = True
        assert len(session.run_detectors()) > 0
        assert not db_path.exists()  # nothing decided -> nothing persisted

    def test_invalid_selection_reprompts(self, tmp_path, monkeypatch, capsys):
        db_path = tmp_path / "velvet.db.json"
        session = Velvet(TX_ORIGIN, disable_color=True, triage_database=str(db_path))
        total = len(session.run_detectors())
        monkeypatch.setattr(sys, "stdin", _FakeStdin("bogus\n99\n0,1\n"))
        session.triage_mode = True
        survivors = session.run_detectors()
        out = capsys.readouterr().out
        assert out.count("Invalid selection") == 2
        assert len(survivors) == total - 2
        assert len(TriageDatabase.load(db_path).hidden_ids) == 2

    def test_non_interactive_stdin_errors_cleanly(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sys, "stdin", io.StringIO(""))  # not a TTY (CI)
        session = Velvet(TX_ORIGIN, disable_color=True, triage_database=str(tmp_path / "d.json"))
        session.triage_mode = True
        with pytest.raises(VelvetError, match="interactive terminal"):
            session.run_detectors()


# ------------------------------------------------------------- checklist
class TestMarkdownRootNormalization:
    @pytest.mark.parametrize(
        "given,expected",
        [
            ("", ""),
            (None, ""),
            ("https://github.com/org/repo", "https://github.com/org/repo/blob/HEAD/"),
            ("https://github.com/org/repo/", "https://github.com/org/repo/blob/HEAD/"),
            ("https://github.com/org/repo/tree/main", "https://github.com/org/repo/blob/main/"),
            (
                "https://github.com/org/repo/tree/dev/x",
                "https://github.com/org/repo/blob/dev/x/",
            ),
            ("https://github.com/org/repo/blob/abc123", "https://github.com/org/repo/blob/abc123/"),
            ("https://github.com/org/repo/blob/abc123/", "https://github.com/org/repo/blob/abc123/"),
        ],
    )
    def test_normalize(self, given, expected):
        assert normalize_markdown_root(given) == expected


class TestChecklist:
    def test_summary_table_and_items(self, session):
        markdown = render_checklist(session.run_detectors())
        assert markdown.startswith("# velvet checklist\n")
        assert "| Rule | Count | Impact |" in markdown
        assert "| tx-origin | 2 | Medium |" in markdown
        assert "| arbitrary-send-eth | 2 | High |" in markdown
        assert "## tx-origin" in markdown
        assert "- [ ] tx-origin-1:" in markdown
        assert "- [ ] tx-origin-2:" in markdown
        # source location links (relative link without a markdown root)
        assert "TxOrigin.sol#L" in markdown
        assert "](fixtures/detectors/TxOrigin.sol" not in markdown  # absolute fixture path

    def test_markdown_root_links(self, session):
        markdown = render_checklist(
            session.run_detectors(), markdown_root="https://github.com/org/repo"
        )
        assert "](https://github.com/org/repo/blob/HEAD/" in markdown
        assert "#L" in markdown.split("](https://github.com/org/repo/blob/HEAD/", 1)[1]

    def test_limit_truncation(self, session):
        markdown = render_checklist(session.run_detectors(), limit=1)
        assert "- [ ] tx-origin-1:" in markdown
        assert "- [ ] tx-origin-2:" not in markdown
        assert "and 1 more tx-origin finding(s)" in markdown
        assert "--checklist-limit" in markdown

    def test_empty_report(self):
        markdown = render_checklist([])
        assert "No findings." in markdown
        assert "| Rule |" not in markdown


# ------------------------------------------------------------- CLI surface
class TestCliFlags:
    def test_new_flags_parse(self):
        args = build_parser().parse_args(
            [
                "target.sol",
                "--triage-mode",
                "--triage-database",
                "x.db.json",
                "--show-ignored-findings",
                "--checklist",
                "--markdown-root",
                "https://github.com/o/r",
                "--checklist-limit",
                "3",
                "--force-framework",
                "hardhat",
                "--etherscan-apikey",
                "KEY",
                "--explorer-network",
                "sepolia",
            ]
        )
        assert args.triage_mode is True
        assert args.triage_database == "x.db.json"
        assert args.show_ignored_findings is True
        assert args.checklist is True
        assert args.markdown_root == "https://github.com/o/r"
        assert args.checklist_limit == 3
        assert args.force_framework == "hardhat"
        assert args.etherscan_apikey == "KEY"
        assert args.explorer_network == "sepolia"

    def test_config_keys_and_cli_precedence(self, tmp_path, monkeypatch, capsys):
        config = {
            "triage_database": str(tmp_path / "cfg.db.json"),
            "show_ignored_findings": True,
            "markdown_root": "https://github.com/cfg/repo",
            "checklist": True,
            "checklist_limit": 1,
            "etherscan_apikey": "KEY",
            "explorer_network": "sepolia",
        }
        (tmp_path / "velvet.config.json").write_text(json.dumps(config))
        monkeypatch.chdir(tmp_path)

        captured: dict = {}
        real_velvet = velvet.cli.Velvet

        def spy(target, **options):
            captured.update(options)
            return real_velvet(target, **options)

        monkeypatch.setattr(velvet.cli, "Velvet", spy)
        assert main([TX_ORIGIN, "--disable-color"]) == 0
        # config keys flowed into the session options
        assert captured["triage_database"] == str(tmp_path / "cfg.db.json")
        assert captured["show_ignored_findings"] is True
        assert captured["markdown_root"] == "https://github.com/cfg/repo"
        assert captured["etherscan_apikey"] == "KEY"
        assert captured["explorer_network"] == "sepolia"
        out = capsys.readouterr().out
        assert "# velvet checklist" in out  # checklist from config
        assert "](https://github.com/cfg/repo/blob/HEAD/" in out
        assert "and 1 more tx-origin" in out  # checklist_limit from config

        # CLI wins over config
        captured.clear()
        assert main([TX_ORIGIN, "--disable-color", "--markdown-root", "https://github.com/cli/repo"]) == 0
        assert captured["markdown_root"] == "https://github.com/cli/repo"

    def test_checklist_flag(self, capsys):
        assert main([TX_ORIGIN, "--disable-color", "--detect", "tx-origin", "--checklist"]) == 0
        out = capsys.readouterr().out
        assert "# velvet checklist" in out
        assert "- [ ] tx-origin-1:" in out

    def test_checklist_suppressed_when_json_stdout(self, capsys):
        assert main([TX_ORIGIN, "--detect", "tx-origin", "--checklist", "--json", "-"]) == 0
        out = capsys.readouterr().out
        assert "# velvet checklist" not in out
        json.loads(out)  # stdout stays machine-parseable

    def test_cli_triage_end_to_end(self, tmp_path, monkeypatch, capsys):
        db_path = tmp_path / "velvet.db.json"
        base = [TX_ORIGIN, "--disable-color", "--detect", "tx-origin"]
        monkeypatch.setattr(sys, "stdin", _FakeStdin("All\n"))
        assert main(base + ["--triage-mode", "--triage-database", str(db_path)]) == 0
        capsys.readouterr()
        assert len(TriageDatabase.load(db_path).hidden_ids) == 2

        # hidden automatically on the next run
        assert main(base + ["--triage-database", str(db_path)]) == 0
        assert "tx-origin (" not in capsys.readouterr().out

        # revealed (marked) with --show-ignored-findings
        assert main(base + ["--triage-database", str(db_path), "--show-ignored-findings"]) == 0
        out = capsys.readouterr().out
        assert "tx-origin (" in out
        assert out.count("[hidden by triage]") == 2

    def test_cli_triage_non_tty_exit_2(self, tmp_path, capsys):
        # pytest's captured stdin is not a TTY: clean error + guidance
        code = main([TX_ORIGIN, "--triage-mode", "--triage-database", str(tmp_path / "d.json")])
        assert code == 2
        assert "interactive terminal" in capsys.readouterr().err
