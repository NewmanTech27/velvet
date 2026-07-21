"""JSON output (spec/architecture.md §10.2, api-surface.md §9).

Top level: ``{success, error, results}``; ``results.detectors`` carries
findings with typed elements (``type_specific_fields.parent`` chains,
``source_mapping`` byte offsets + 1-based line/column spans).  Output is
deterministic: stable ordering, byte-stable across identical runs.

Original clean-room implementation.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from velvet.detectors.base import Finding, classify_element, element_name

JSON_TYPES = (
    "detectors",
    "printers",
    "compilations",
    "console",
    "list-detectors",
    "list-printers",
)


# ------------------------------------------------------------ serialization
def _parent_of(element: Any) -> Any:
    from velvet.core.cfg_node import CFGNode
    from velvet.core.declarations import CustomError, Enum, Event, Structure
    from velvet.core.function import FunctionLike
    from velvet.core.variables import LocalVariable, StateVariable

    if isinstance(element, CFGNode):
        return element.function
    if isinstance(element, FunctionLike):
        return element.contract_declarer or element.contract
    if isinstance(element, StateVariable):
        return element.contract
    if isinstance(element, LocalVariable):
        return element.function
    if isinstance(element, (Event, Structure, Enum, CustomError)):
        return element.contract
    return None


def element_to_dict(element: Any) -> dict[str, Any]:
    """Serialize one finding element (§10.2), incl. parent chain."""
    kind = classify_element(element)
    result: dict[str, Any] = {"type": kind, "name": element_name(element)}
    source_mapping = getattr(element, "source_mapping", None)
    if source_mapping is not None and source_mapping.filename is not None:
        result["source_mapping"] = source_mapping.to_dict()
    type_specific: dict[str, Any] = {}
    parent = _parent_of(element)
    if parent is not None:
        type_specific["parent"] = element_to_dict(parent)
    signature = getattr(element, "signature", None)
    if kind in ("function", "event") and signature:
        type_specific["signature"] = signature
    if kind == "pragma":
        type_specific["directive"] = list(getattr(element, "directive", []))
    if type_specific:
        result["type_specific_fields"] = type_specific
    return result


def finding_to_dict(
    finding: Finding, *, patches: Optional[dict[str, Any]] = None
) -> dict[str, Any]:
    """Serialize one finding (§10.2); ``patches`` is the optional
    machine-applicable patch object (§10.5, ``--generate-patches``)."""
    result: dict[str, Any] = {
        "check": finding.check,
        "impact": finding.impact.value,
        "confidence": finding.confidence.value,
        "description": finding.description,
        "markdown": finding.markdown,
        "first_markdown_element": finding.first_markdown_element,
        "id": finding.id,
        "elements": [element_to_dict(e) for e in finding.elements],
    }
    if patches:
        result["patches"] = patches
    if finding.additional_fields:
        result["additional_fields"] = finding.additional_fields
    return result


# ---------------------------------------------------------------- assembly
def detector_listing(session: Any) -> list[dict[str, Any]]:
    return [
        {
            "check": d.RULE,
            "title": d.TITLE,
            "impact": d.IMPACT.value,
            "confidence": d.CONFIDENCE.value,
            "docs_url": d.DOCS.url,
        }
        for d in sorted(session.registered_detectors, key=lambda x: x.RULE)
    ]


def printer_listing(session: Any) -> list[dict[str, Any]]:
    return [
        {"printer": p.RULE, "title": p.TITLE}
        for p in sorted(session.registered_printers, key=lambda x: x.RULE)
    ]


def compilation_listing(session: Any) -> list[dict[str, Any]]:
    compilations: list[dict[str, Any]] = []
    for unit in session.compilation_units:
        artifacts = unit.compilation
        compilations.append(
            {
                "compiler_version": artifacts.compiler_version,
                "source_units": [
                    info.filename.absolute for info in artifacts.source_units.values()
                ],
            }
        )
    return compilations


def build_json_output(
    session: Any,
    findings: Optional[list[Finding]] = None,
    *,
    printer_results: Optional[list[str]] = None,
    json_types: Optional[list[str]] = None,
    console_text: Optional[str] = None,
    success: bool = True,
    error: Optional[str] = None,
) -> dict[str, Any]:
    """Assemble the top-level JSON document (§10.2)."""
    requested = list(json_types) if json_types else ["detectors"]
    unknown = [t for t in requested if t not in JSON_TYPES]
    if unknown:
        raise ValueError(
            f"Unknown json-types {unknown}; expected among {list(JSON_TYPES)}"
        )
    results: dict[str, Any] = {}
    if "detectors" in requested:
        generate_patches = bool(getattr(session, "generate_patches", False))
        serialized = []
        for finding in findings or []:
            patches = None
            if generate_patches:
                from velvet.outputs.patches import finding_patches_dict

                patches = finding_patches_dict(finding, session)
            serialized.append(finding_to_dict(finding, patches=patches))
        results["detectors"] = serialized
    if "printers" in requested:
        results["printers"] = list(printer_results or [])
    if "compilations" in requested:
        results["compilations"] = compilation_listing(session)
    if "console" in requested:
        results["console"] = console_text or ""
    if "list-detectors" in requested:
        results["list-detectors"] = detector_listing(session)
    if "list-printers" in requested:
        results["list-printers"] = printer_listing(session)
    return {"success": success, "error": error, "results": results}


def dump_json(document: dict[str, Any]) -> str:
    """Deterministic JSON text (byte-stable across identical runs)."""
    return json.dumps(document, indent=2) + "\n"
