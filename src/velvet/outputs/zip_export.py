"""Zip results export (spec/architecture.md §10.4,
spec/printers-and-tools.md §C.3 ``--zip`` / ``--zip-type``).

``--zip FILE`` bundles the full JSON results (detectors, printers when run,
compilation info, console text) plus the plain console text into a single
compressed zip archive.  ``--zip-type`` selects the compression: ``lzma``
(default), ``zlib`` or ``stored`` (uncompressed).

Archive members:

- ``results.json`` — the standard JSON document (§10.2) with the
  ``detectors``, ``printers`` (when any printer ran), ``compilations`` and
  ``console`` sections;
- ``console.txt``  — the human-readable console rendering.

Original clean-room implementation.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any, Optional

from velvet.detectors.base import Finding
from velvet.outputs.json_out import build_json_output, dump_json

#: Member carrying the machine-readable results.
RESULTS_MEMBER = "results.json"
#: Member carrying the console rendering.
CONSOLE_MEMBER = "console.txt"

#: ``--zip-type`` name -> zipfile compression constant.
ZIP_TYPES = {
    "lzma": zipfile.ZIP_LZMA,
    "zlib": zipfile.ZIP_DEFLATED,
    "stored": zipfile.ZIP_STORED,
}

DEFAULT_ZIP_TYPE = "lzma"


def write_zip_export(
    session: Any,
    findings: list[Finding],
    path: Any,
    *,
    zip_type: str = DEFAULT_ZIP_TYPE,
    printer_results: Optional[list[str]] = None,
    console_text: Optional[str] = None,
) -> Path:
    """Bundle the full results into a compressed zip archive."""
    compression = ZIP_TYPES.get(zip_type)
    if compression is None:
        raise ValueError(
            f"Unknown zip-type {zip_type!r}; expected one of {sorted(ZIP_TYPES)}"
        )
    json_types = ["detectors", "compilations", "console"]
    if printer_results:
        json_types.insert(1, "printers")
    document = build_json_output(
        session,
        findings,
        printer_results=printer_results,
        json_types=json_types,
        console_text=console_text,
    )
    out_path = Path(path)
    parent = out_path.parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", compression=compression) as archive:
        archive.writestr(RESULTS_MEMBER, dump_json(document))
        archive.writestr(CONSOLE_MEMBER, console_text or "")
    return out_path
