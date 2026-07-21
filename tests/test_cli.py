"""CLI smoke tests (api-surface.md §7).

Original clean-room implementation.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from velvet.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
TX_ORIGIN = str(FIXTURES / "detectors" / "TxOrigin.sol")
SOLC_VERSION = str(FIXTURES / "detectors" / "SolcVersion.sol")


def _run(argv: list[str]) -> tuple[int, str, str]:
    """Invoke the real CLI entry point in-process, capturing output."""
    from io import StringIO

    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = StringIO(), StringIO()
    try:
        code = main(argv)
        return code, sys.stdout.getvalue(), sys.stderr.getvalue()
    finally:
        sys.stdout, sys.stderr = old_out, old_err


class TestListings:
    def test_list_detectors(self, capsys):
        assert main(["--list-detectors"]) == 0
        out = capsys.readouterr().out
        for rule in ("tx-origin", "pragma", "solc-version"):
            assert rule in out
        assert "Impact" in out

    def test_list_printers(self, capsys):
        assert main(["--list-printers"]) == 0

    def test_version(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        assert "velvet" in capsys.readouterr().out


class TestRun:
    def test_console_findings(self, capsys):
        code = main([TX_ORIGIN, "--disable-color"])
        out = capsys.readouterr().out
        assert "tx-origin" in out
        assert "TxOrigin.sol#L" in out
        assert code == 0  # default fail-on: none

    def test_json_stdout(self, capsys):
        code = main([TX_ORIGIN, "--json", "-"])
        out = capsys.readouterr().out
        doc = json.loads(out)
        assert doc["success"] is True
        assert doc["results"]["detectors"]
        # pure JSON on stdout: console findings suppressed
        assert "tx-origin (" not in out.split('"success"')[0]
        assert code == 0

    def test_json_file_and_types(self, tmp_path, capsys):
        target = tmp_path / "out.json"
        code = main(
            [TX_ORIGIN, "--json", str(target), "--json-types", "detectors,list-detectors"]
        )
        assert code == 0
        doc = json.loads(target.read_text())
        assert "detectors" in doc["results"]
        assert "list-detectors" in doc["results"]

    def test_sarif_file(self, tmp_path):
        target = tmp_path / "out.sarif"
        code = main([TX_ORIGIN, "--sarif", str(target)])
        assert code == 0
        sarif = json.loads(target.read_text())
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"]

    def test_fail_on(self, capsys):
        # MEDIUM finding exists -> medium fails, high passes
        assert main([TX_ORIGIN, "--detect", "tx-origin", "--fail-on", "medium"]) == 1
        assert main([TX_ORIGIN, "--detect", "tx-origin", "--fail-on", "high"]) == 0

    def test_detect_selection(self, capsys):
        code = main([SOLC_VERSION, "--detect", "solc-version", "--fail-on", "pedantic"])
        out = capsys.readouterr().out
        assert "solc-version" in out
        assert "tx-origin" not in out
        assert code == 1

    def test_exclude(self, capsys):
        code = main([TX_ORIGIN, "--exclude", "tx-origin"])
        out = capsys.readouterr().out
        assert "tx-origin (" not in out
        assert code == 0

    def test_exclude_impact(self, capsys):
        # MEDIUM class excluded; single consistent pragma means nothing else
        # remains, so pedantic passes.
        code = main(
            [TX_ORIGIN, "--detect", "tx-origin", "--exclude-medium", "--fail-on", "pedantic"]
        )
        out = capsys.readouterr().out
        assert "tx-origin" not in out
        assert code == 0

    def test_filter_paths(self, capsys):
        code = main([TX_ORIGIN, "--filter-paths", "TxOrigin"])
        out = capsys.readouterr().out
        assert "tx-origin (" not in out
        assert code == 0

    def test_config_file_and_cli_precedence(self, tmp_path, capsys, monkeypatch):
        config = tmp_path / "velvet.config.json"
        config.write_text(json.dumps({"fail_on": "pedantic", "disable_color": True}))
        monkeypatch.chdir(tmp_path)
        # config alone -> pedantic -> fail on any finding
        assert main([TX_ORIGIN]) == 1
        # CLI wins over config
        assert main([TX_ORIGIN, "--detect", "tx-origin", "--fail-on", "high"]) == 0

    def test_missing_target_errors(self):
        with pytest.raises(SystemExit):
            main([])

    def test_bad_target_exit_2(self, capsys):
        code = main([str(FIXTURES / "does-not-exist.sol")])
        assert code == 2
