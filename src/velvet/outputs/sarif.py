"""SARIF v2.1.0 export (spec/architecture.md §10.3, api-surface.md §9).

One SARIF ``rule`` per detector (rule id, help, docs URL), one ``result``
per finding with ``level`` mapped from impact (HIGH -> error,
MEDIUM -> warning, else note), primary location from the finding's first
element, related locations from the remaining elements, and
``partialFingerprints`` from the finding's stable identity hash.

Triage export (``--sarif-triage``, architecture.md §10.3): the triage
variant includes every finding — visible and triage-hidden — and records
the suppression state on each result: hidden findings get
``suppressions: [{"kind": "external", ...}]`` and
``baselineState: "unchanged"``; visible findings get
``baselineState: "new"``.  The file round-trips through
:func:`velvet.triage.import_sarif_triage` and is suitable for SARIF
explorers.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Optional

import velvet
from velvet.detectors.base import Detector, Finding, Impact

_LEVELS = {
    Impact.HIGH: "error",
    Impact.MEDIUM: "warning",
    Impact.LOW: "note",
    Impact.INFORMATIONAL: "note",
    Impact.OPTIMIZATION: "note",
}

_HOMEPAGE = "https://github.com/velvet-analyzer/velvet"


def _physical_location(element: Any) -> Optional[dict[str, Any]]:
    source_mapping = getattr(element, "source_mapping", None)
    if source_mapping is None or source_mapping.filename is None:
        return None
    if not source_mapping.lines:
        return None
    region: dict[str, Any] = {
        "startLine": source_mapping.lines[0],
        "endLine": source_mapping.lines[-1],
    }
    if source_mapping.starting_column:
        region["startColumn"] = source_mapping.starting_column
    if source_mapping.ending_column:
        region["endColumn"] = source_mapping.ending_column
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": source_mapping.filename.relative},
            "region": region,
        }
    }


def _rule_for(detector_class: type[Detector]) -> dict[str, Any]:
    return {
        "id": detector_class.RULE,
        "name": detector_class.__name__,
        "shortDescription": {"text": detector_class.TITLE},
        "fullDescription": {"text": detector_class.DOCS.description or detector_class.TITLE},
        "helpUri": detector_class.DOCS.url or _HOMEPAGE,
        "help": {
            "text": detector_class.DOCS.recommendation or detector_class.TITLE,
        },
        "properties": {
            "impact": detector_class.IMPACT.value,
            "confidence": detector_class.CONFIDENCE.value,
        },
    }


#: SARIF suppression kind used for triage-hidden findings (external triage
#: decision, not an in-source suppression comment).
TRIAGE_SUPPRESSION_KIND = "external"


def _result_for(finding: Finding, *, triage: bool = False) -> dict[str, Any]:
    locations: list[dict[str, Any]] = []
    related: list[dict[str, Any]] = []
    seen_primary = False
    related_id = 1
    for element in finding.elements:
        if isinstance(element, str):
            continue
        location = _physical_location(element)
        if location is None:
            continue
        if not seen_primary:
            locations.append(location)
            seen_primary = True
        else:
            location = dict(location)
            location["id"] = related_id
            related_id += 1
            related.append(location)
    result: dict[str, Any] = {
        "ruleId": finding.check,
        "level": _LEVELS.get(finding.impact, "note"),
        "message": {"text": finding.description},
        "partialFingerprints": {"velvet/finding-id": finding.id},
    }
    if locations:
        result["locations"] = locations
    if related:
        result["relatedLocations"] = related
    if triage:
        if getattr(finding, "hidden", False):
            result["suppressions"] = [
                {
                    "kind": TRIAGE_SUPPRESSION_KIND,
                    "justification": "hidden by velvet triage",
                }
            ]
            result["baselineState"] = "unchanged"
        else:
            result["baselineState"] = "new"
    return result


def build_sarif(
    session: Any, findings: list[Finding], *, triage: bool = False
) -> dict[str, Any]:
    """Assemble the SARIF v2.1.0 document (§10.3).

    With ``triage=True`` the results carry the suppression state (hidden
    findings must be included in ``findings``, marked ``hidden = True``).
    """
    used_rules = sorted({f.check for f in findings})
    detector_classes = {d.RULE: d for d in session.registered_detectors}
    rules = [
        _rule_for(detector_classes[rule]) for rule in used_rules if rule in detector_classes
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "velvet",
                        "version": velvet.__version__,
                        "informationUri": _HOMEPAGE,
                        "rules": rules,
                    }
                },
                "results": [_result_for(f, triage=triage) for f in findings],
            }
        ],
    }
