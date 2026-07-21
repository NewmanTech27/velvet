"""Machine-applicable patches (spec/architecture.md §10.5,
spec/printers-and-tools.md §C.3 ``--generate-patches``).

An opt-in mode (session option ``generate_patches``, CLI ``--generate-patches``)
attaches **machine-applicable patches** to findings in the JSON output, for
tooling that auto-fixes simple issues.  Patches are produced by a small
*patch-provider registry*: detectors declare a patch generator keyed by their
rule id, and the JSON layer asks the registry for each finding.

Patch JSON schema (``velvet-patches-v1``)
-----------------------------------------

Each patched finding carries a ``patches`` object::

    "patches": {
      "format": "velvet-patches-v1",
      "edits": [
        {
          "filename": "<path as used on the command line>",
          "filename_relative": "<repo/cwd-relative path>",
          "filename_absolute": "<absolute path>",
          "start": 170,                // byte offset into the source text
          "length": 0,                 // bytes replaced (0 = pure insertion)
          "replacement": "constant ",  // new text spliced in at [start, start+length)
          "description": "declare maxFeeBps constant"
        }
      ]
    }

Edits apply at exact source offsets taken from the finding's
``source_mapping``.  Applying a finding's patches to a file means splicing
each edit's ``replacement`` over the ``[start, start + length)`` span of the
**original** text; :func:`apply_edits_to_source` does this (descending offset
order, overlapping edits are rejected).  Findings whose detector has no
registered provider — or whose provider cannot locate a safe edit — carry no
``patches`` key at all.

Wired providers (mechanical, safe fixes only):

- ``solc-version``       — replace the pragma version range with the
  recommended pinned solc (``pragma solidity 0.8.24;``).
- ``pragma``             — unify an inconsistent pragma to the anchor
  (first) pragma's version expression.
- ``constable-states``   — insert ``constant`` in the declaration.
- ``immutable-states``   — insert ``immutable`` in the declaration.
- ``naming-convention``  — rename the declared identifier to the violated
  convention (declaration site only; references are not rewritten).

``--patches-dir DIR`` additionally writes one unified-diff ``.patch`` file
per patched finding (git-style ``a/`` ``b/`` headers).

Original clean-room implementation.
"""

from __future__ import annotations

import difflib
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from velvet.detectors.base import Finding

logger = logging.getLogger("velvet.outputs.patches")

#: Version tag of the patch JSON schema (see module docstring).
PATCH_FORMAT = "velvet-patches-v1"

#: Recommended pinned compiler used by the ``solc-version`` patch
#: (the detector's documented recommendation example).
RECOMMENDED_SOLC_VERSION = "0.8.24"

_NAME_BOUNDARY = r"[A-Za-z0-9_$]"
_PRAGMA_HEAD_RE = re.compile(r"pragma\s+solidity\s+")


# ------------------------------------------------------------------- edits
@dataclass(frozen=True)
class PatchEdit:
    """One source-to-source edit at an exact byte-offset span."""

    filename: str  # path as used on the command line
    filename_relative: str
    filename_absolute: str
    start: int  # byte offset into the source text
    length: int  # bytes replaced (0 = pure insertion)
    replacement: str  # new text for [start, start + length)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "filename_relative": self.filename_relative,
            "filename_absolute": self.filename_absolute,
            "start": self.start,
            "length": self.length,
            "replacement": self.replacement,
            "description": self.description,
        }


def apply_edits_to_source(source: str, edits: list[PatchEdit]) -> str:
    """Apply edits to ``source`` (original text); overlapping spans rejected."""
    ordered = sorted(edits, key=lambda e: (e.start, e.length))
    for prev, nxt in zip(ordered, ordered[1:]):
        if nxt.start < prev.start + prev.length:
            raise ValueError(
                f"overlapping patch edits at offsets {prev.start} and {nxt.start}"
            )
    patched = source
    for edit in sorted(edits, key=lambda e: e.start, reverse=True):
        patched = patched[: edit.start] + edit.replacement + patched[edit.start + edit.length :]
    return patched


# ---------------------------------------------------------------- registry
PatchProvider = Callable[[Finding, Any], list[PatchEdit]]

_PROVIDERS: dict[str, PatchProvider] = {}


def register_patch_provider(
    rule: str, provider: Optional[PatchProvider] = None
) -> Any:
    """Register a patch generator for a detector rule (decorator-friendly).

    A provider receives ``(finding, session)`` and returns the edits that
    mechanically fix the finding (empty list when no safe edit exists).
    """

    def decorator(fn: PatchProvider) -> PatchProvider:
        _PROVIDERS[rule] = fn
        return fn

    if provider is not None:
        return decorator(provider)
    return decorator


def patch_provider_for(rule: str) -> Optional[PatchProvider]:
    return _PROVIDERS.get(rule)


def patches_for_finding(finding: Finding, session: Any) -> list[PatchEdit]:
    """Edits for one finding; empty when the rule has no provider or the
    provider cannot locate a safe edit (providers never raise)."""
    provider = _PROVIDERS.get(finding.check)
    if provider is None:
        return []
    try:
        return list(provider(finding, session))
    except Exception:  # noqa: BLE001 - patch generation is best-effort
        logger.warning("Patch provider for %s failed", finding.check, exc_info=True)
        return []


def finding_patches_dict(finding: Finding, session: Any) -> Optional[dict[str, Any]]:
    """JSON-ready ``patches`` object for a finding (``None`` = no key)."""
    edits = patches_for_finding(finding, session)
    if not edits:
        return None
    return {"format": PATCH_FORMAT, "edits": [e.to_dict() for e in edits]}


# ------------------------------------------------------------ shared helpers
def _span_of(element: Any, session: Any) -> Optional[tuple[str, Any]]:
    """(source text, source_mapping) of an element, when fully mapped."""
    source_mapping = getattr(element, "source_mapping", None)
    if source_mapping is None or source_mapping.filename is None:
        return None
    source = session.source_code(source_mapping.filename.absolute)
    if not source:
        return None
    return source, source_mapping


def _make_edit(source_mapping: Any, start: int, length: int, replacement: str, description: str) -> PatchEdit:
    filename = source_mapping.filename
    return PatchEdit(
        filename=filename.used,
        filename_relative=filename.relative,
        filename_absolute=filename.absolute,
        start=start,
        length=length,
        replacement=replacement,
        description=description,
    )


def _name_occurrence(text: str, name: str) -> Optional[re.Match[str]]:
    """First whole-identifier occurrence of ``name`` inside ``text``."""
    return re.search(
        rf"(?<!{_NAME_BOUNDARY}){re.escape(name)}(?!{_NAME_BOUNDARY})", text
    )


def _elements_of_type(finding: Finding, types: Any) -> list[Any]:
    return [e for e in finding.elements if not isinstance(e, str) and isinstance(e, types)]


def _pragma_version_span(source: str, source_mapping: Any) -> Optional[tuple[int, int]]:
    """Absolute (start, length) of the version expression inside a
    ``pragma solidity <version>;`` statement span."""
    text = source[source_mapping.start : source_mapping.start + source_mapping.length]
    stripped = text.strip()
    head = _PRAGMA_HEAD_RE.match(stripped)
    if head is None:
        return None
    leading = len(text) - len(text.lstrip())
    version_start = leading + head.end()
    semicolon = text.find(";", version_start)
    version_end = semicolon if semicolon != -1 else len(text.rstrip())
    return source_mapping.start + version_start, version_end - version_start


def _insert_keyword_edit(
    var: Any, session: Any, keyword: str
) -> list[PatchEdit]:
    """Insert ``keyword `` right before the variable name in its declaration
    span (``uint256 public maxFeeBps = 500`` -> ``uint256 public constant
    maxFeeBps = 500``)."""
    located = _span_of(var, session)
    if located is None:
        return []
    source, source_mapping = located
    text = source[source_mapping.start : source_mapping.start + source_mapping.length]
    if keyword in text.split():  # already declared with the keyword
        return []
    match = _name_occurrence(text, var.name)
    if match is None:
        return []
    return [
        _make_edit(
            source_mapping,
            source_mapping.start + match.start(),
            0,
            f"{keyword} ",
            f"declare {var.name} {keyword}",
        )
    ]


def _replace_version_edit(
    pragma: Any, session: Any, new_version: str, description: str
) -> list[PatchEdit]:
    located = _span_of(pragma, session)
    if located is None:
        return []
    source, source_mapping = located
    span = _pragma_version_span(source, source_mapping)
    if span is None:
        return []
    start, length = span
    return [_make_edit(source_mapping, start, length, new_version, description)]


# ------------------------------------------------------- wired providers (5)
@register_patch_provider("solc-version")
def _solc_version_patches(finding: Finding, session: Any) -> list[PatchEdit]:
    """Replace the pragma range with the recommended pinned solc."""
    from velvet.core.declarations import PragmaDirective

    pragmas = _elements_of_type(finding, PragmaDirective)
    if not pragmas:
        return []
    return _replace_version_edit(
        pragmas[0],
        session,
        RECOMMENDED_SOLC_VERSION,
        f"pin pragma to the recommended solc {RECOMMENDED_SOLC_VERSION}",
    )


@register_patch_provider("pragma")
def _pragma_patches(finding: Finding, session: Any) -> list[PatchEdit]:
    """Unify every conflicting pragma to the anchor (first) pragma's version."""
    from velvet.core.declarations import PragmaDirective

    pragmas = _elements_of_type(finding, PragmaDirective)
    if len(pragmas) < 2:
        return []
    anchor, others = pragmas[0], pragmas[1:]
    edits: list[PatchEdit] = []
    for other in others:
        edits.extend(
            _replace_version_edit(
                other,
                session,
                anchor.version,
                f"unify pragma with {anchor.version}",
            )
        )
    return edits


@register_patch_provider("constable-states")
def _constable_states_patches(finding: Finding, session: Any) -> list[PatchEdit]:
    """Insert ``constant`` into the flagged state variable declaration."""
    from velvet.core.variables import StateVariable

    variables = _elements_of_type(finding, StateVariable)
    if not variables:
        return []
    return _insert_keyword_edit(variables[0], session, "constant")


@register_patch_provider("immutable-states")
def _immutable_states_patches(finding: Finding, session: Any) -> list[PatchEdit]:
    """Insert ``immutable`` into the flagged state variable declaration."""
    from velvet.core.variables import StateVariable

    variables = _elements_of_type(finding, StateVariable)
    if not variables:
        return []
    return _insert_keyword_edit(variables[0], session, "immutable")


# ------------------------------------------------------- naming-convention
def _identifier_words(name: str) -> list[str]:
    """Split an identifier into words (snake/camel/Pascal/UPPER aware)."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    spaced = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", spaced)
    return [w for w in re.split(r"[_\s]+", spaced) if w]


def convert_identifier(name: str, convention: str) -> str:
    """Rename ``name`` to ``convention`` (leading underscores preserved)."""
    prefix = name[: len(name) - len(name.lstrip("_"))]
    words = _identifier_words(name.lstrip("_"))
    if not words:
        return name
    if convention == "CapWords":
        core = "".join(w[:1].upper() + w[1:].lower() for w in words)
    elif convention == "mixedCase":
        core = words[0].lower() + "".join(
            w[:1].upper() + w[1:].lower() for w in words[1:]
        )
    elif convention == "UPPER_CASE_WITH_UNDERSCORES":
        core = "_".join(w.upper() for w in words)
    else:
        return name
    return prefix + core


@register_patch_provider("naming-convention")
def _naming_convention_patches(finding: Finding, session: Any) -> list[PatchEdit]:
    """Rename the declared identifier to the violated convention (declaration
    site only)."""
    convention = finding.additional_fields.get("convention", "")
    if not convention:
        return []
    element = finding.primary_element
    name = getattr(element, "name", "") or ""
    if not name:
        return []
    new_name = convert_identifier(name, convention)
    if new_name == name:
        return []
    located = _span_of(element, session)
    if located is None:
        return []
    source, source_mapping = located
    text = source[source_mapping.start : source_mapping.start + source_mapping.length]
    match = _name_occurrence(text, name)
    if match is None:
        return []
    return [
        _make_edit(
            source_mapping,
            source_mapping.start + match.start(),
            len(name),
            new_name,
            f"rename {name} to {new_name} ({convention})",
        )
    ]


# --------------------------------------------------------------- diff files
def render_unified_diff(filename_used: str, original: str, patched: str) -> str:
    """Git-style unified diff of one file (``a/`` -> ``b/`` headers)."""
    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile=f"a/{filename_used}",
        tofile=f"b/{filename_used}",
    )
    return "".join(diff)


def write_patch_files(
    session: Any, findings: list[Finding], directory: Any
) -> list[Path]:
    """Write one unified-diff ``.patch`` file per patched finding into
    ``directory``; returns the written paths (deterministic order)."""
    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    index = 0
    for finding in findings:
        edits = patches_for_finding(finding, session)
        if not edits:
            continue
        by_file: dict[str, list[PatchEdit]] = {}
        for edit in edits:
            by_file.setdefault(edit.filename_absolute, []).append(edit)
        chunks: list[str] = []
        for path in sorted(by_file):
            file_edits = by_file[path]
            original = session.source_code(path)
            patched = apply_edits_to_source(original, file_edits)
            chunks.append(render_unified_diff(file_edits[0].filename, original, patched))
        index += 1
        out_path = out_dir / f"{index:04d}-{finding.check}-{finding.id[:8]}.patch"
        out_path.write_text("".join(chunks))
        written.append(out_path)
    return written
