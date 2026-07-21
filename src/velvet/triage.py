"""Interactive triage mode and the persistent triage database
(spec/architecture.md §11 item 4, spec/printers-and-tools.md §C.6).

Triage is the **last** stage of the filtering pipeline (after inline
suppressions, path filters and dependency exclusion):

- ``--triage-mode`` lists every surviving finding with an index and prompts
  ``Results to hide during next runs: "0,1,..." or "All" (enter to not hide
  results)``; the selected findings' stable identity hashes
  (:attr:`velvet.detectors.base.Finding.id`) are persisted to a local JSON
  database (default ``velvet.db.json``, configurable via the
  ``triage_database`` option).
- Subsequent runs hide recorded findings automatically; deleting the
  database restores them.
- ``--show-ignored-findings`` keeps hidden findings visible, marked with
  ``hidden = True`` (rendered ``[hidden by triage]`` on the console).
- Unknown/stale ids in the database are ignored gracefully, and an
  unreadable/corrupt database is treated as empty (triage state must never
  crash an analysis run).
- Non-interactive stdin (CI) raises a clean :class:`VelvetError` with
  guidance instead of hanging on a prompt.

SARIF triage workflow (architecture.md §10.3, printers-and-tools.md §C.4.3):

- ``--sarif-input FILE`` seeds/merges triage state from an existing SARIF
  file before filtering: results carrying ``suppressions`` or a baseline
  state (``unchanged``/``updated``) are recorded in the triage database
  (keyed by their ``partialFingerprints``/``fingerprints`` values), so the
  corresponding findings are hidden like any triage-hidden finding.
- ``--sarif-triage FILE`` (see :mod:`velvet.outputs.sarif`) exports a triage
  SARIF whose results include the suppression state, suitable for a SARIF
  explorer.

Original clean-room implementation.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable, Optional

from velvet.detectors.base import Finding
from velvet.exceptions import VelvetError

if TYPE_CHECKING:
    from velvet.session import Velvet

logger = logging.getLogger("velvet.triage")

#: Default database file name (session option / config key ``triage_database``).
DEFAULT_DATABASE = "velvet.db.json"

#: Interactive prompt (documented wording, printers-and-tools.md §C.6).
PROMPT = 'Results to hide during next runs: "0,1,..." or "All" (enter to not hide results) '


class TriageDatabase:
    """JSON file of hide decisions keyed by the findings' identity hashes."""

    VERSION = 1

    def __init__(self, path: Any) -> None:
        self.path = Path(path)
        # finding id -> small human-readable record (check/impact/description)
        self.entries: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------ i/o
    @classmethod
    def load(cls, path: Any) -> "TriageDatabase":
        """Load a database; missing/corrupt files yield an empty database."""
        database = cls(path)
        if not database.path.is_file():
            return database
        try:
            raw = json.loads(database.path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "Ignoring unreadable triage database %s: %s", database.path, exc
            )
            return database
        hidden = raw.get("hidden", {}) if isinstance(raw, dict) else {}
        if isinstance(hidden, dict):
            for finding_id, record in hidden.items():
                database.entries[str(finding_id)] = record if isinstance(record, dict) else {}
        elif isinstance(hidden, list):  # tolerate a plain list of ids
            for finding_id in hidden:
                database.entries[str(finding_id)] = {}
        return database

    def save(self) -> None:
        """Persist the database (parent directories created as needed)."""
        parent = self.path.parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": self.VERSION,
            "hidden": {key: self.entries[key] for key in sorted(self.entries)},
        }
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    # -------------------------------------------------------------- queries
    @property
    def hidden_ids(self) -> set[str]:
        return set(self.entries)

    def is_hidden(self, finding_id: str) -> bool:
        return finding_id in self.entries

    def hide(self, findings: Iterable[Finding]) -> None:
        """Record hide decisions for the given findings (idempotent)."""
        for finding in findings:
            self.entries[finding.id] = {
                "check": finding.check,
                "impact": finding.impact.value,
                "description": finding.description,
            }


# ------------------------------------------------------------ interactive
def _render_indexed(session: "Velvet", findings: list[Finding], out: Callable[[str], Any]) -> None:
    """Print each finding with its selection index."""
    from velvet.outputs.console import render_finding_console

    for index, finding in enumerate(findings):
        block = render_finding_console(
            finding,
            disable_color=session.disable_color,
            line_prefix=session.change_line_prefix,
        )
        out(f"[{index}] {block}")


def _parse_selection(answer: str, count: int) -> Optional[list[int]]:
    """Parse a prompt answer into indices; ``None`` means invalid."""
    try:
        indices = sorted({int(piece) for piece in answer.split(",") if piece.strip()})
    except ValueError:
        return None
    if not indices or indices[0] < 0 or indices[-1] >= count:
        return None
    return indices


def interactive_triage(
    session: "Velvet",
    findings: list[Finding],
    database: TriageDatabase,
    *,
    input_fn: Optional[Callable[[str], str]] = None,
    out: Callable[[str], Any] = print,
) -> None:
    """Show indexed findings and persist the user's hide selections.

    Raises :class:`VelvetError` with guidance when stdin is not a TTY
    (e.g. CI), so triage mode fails cleanly instead of hanging.
    """
    if not findings:
        return
    if input_fn is None:
        if not sys.stdin.isatty():
            raise VelvetError(
                "--triage-mode requires an interactive terminal, but stdin is not a TTY. "
                "Run velvet interactively to select findings to hide, manage "
                f"{database.path} manually, or drop --triage-mode."
            )
        input_fn = input
    _render_indexed(session, findings, out)
    while True:
        try:
            answer = input_fn(PROMPT)
        except EOFError:
            return  # stdin closed: treat like "enter" (hide nothing)
        answer = (answer or "").strip()
        if not answer:
            return  # enter: hide nothing
        if answer.lower() == "all":
            database.hide(findings)
            database.save()
            return
        indices = _parse_selection(answer, len(findings))
        if indices is None:
            out(
                f'Invalid selection {answer!r}: enter comma-separated indices '
                f'between 0 and {len(findings) - 1} (e.g. "0,2"), "All", '
                "or press enter to hide nothing."
            )
            continue
        database.hide(findings[index] for index in indices)
        database.save()
        return


# ----------------------------------------------------------- SARIF import
def _result_is_triaged(result: dict[str, Any]) -> bool:
    """True when a SARIF result is suppressed or carries a baseline state."""
    suppressions = result.get("suppressions")
    if isinstance(suppressions, list) and suppressions:
        return True
    baseline = result.get("baselineState")
    return baseline in ("unchanged", "updated")


def _result_fingerprints(result: dict[str, Any]) -> list[str]:
    """Stable identity values of a SARIF result (any fingerprint bag)."""
    fingerprints: list[str] = []
    for key in ("partialFingerprints", "fingerprints"):
        bag = result.get(key)
        if isinstance(bag, dict):
            fingerprints.extend(str(value) for value in bag.values())
    return fingerprints


def import_sarif_triage(database: TriageDatabase, sarif_path: Any) -> int:
    """Merge triage state from an existing SARIF file into ``database``.

    Results marked suppressed (``suppressions``) or baselined
    (``baselineState`` ``unchanged``/``updated``) are recorded as hidden,
    keyed by their fingerprint values (velvet finding ids exported under
    ``velvet/finding-id`` match directly).  Returns the number of newly
    recorded ids.  An unreadable/corrupt file is a no-op (triage state must
    never crash an analysis run).
    """
    path = Path(sarif_path)
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Ignoring unreadable SARIF input %s: %s", path, exc)
        return 0
    added = 0
    runs = raw.get("runs", []) if isinstance(raw, dict) else []
    for run in runs if isinstance(runs, list) else []:
        results = run.get("results", []) if isinstance(run, dict) else []
        for result in results if isinstance(results, list) else []:
            if not isinstance(result, dict) or not _result_is_triaged(result):
                continue
            for fingerprint in _result_fingerprints(result):
                if fingerprint not in database.entries:
                    database.entries[fingerprint] = {
                        "check": str(result.get("ruleId", "")),
                        "source": "sarif-input",
                    }
                    added += 1
    return added


# --------------------------------------------------------------- pipeline
def apply_triage(session: "Velvet", findings: list[Finding]) -> list[Finding]:
    """Triage stage of the filtering pipeline (architecture.md §11, last).

    In triage mode the findings are listed and the user is prompted first;
    afterwards the (possibly updated) database is applied: hidden findings
    are dropped, unless ``show_ignored_findings`` keeps them visible marked
    with ``hidden = True``.  When ``sarif_input`` is configured, triage state
    from that SARIF file is merged into the database first.
    """
    database = TriageDatabase.load(session.triage_database)
    sarif_input = getattr(session, "sarif_input", "")
    if sarif_input and import_sarif_triage(database, sarif_input):
        database.save()
    if session.triage_mode:
        interactive_triage(session, findings, database)
    if session.show_ignored_findings:
        for finding in findings:
            if database.is_hidden(finding.id):
                finding.hidden = True  # marked as hidden (dynamic attribute)
        return findings
    return [finding for finding in findings if not database.is_hidden(finding.id)]
