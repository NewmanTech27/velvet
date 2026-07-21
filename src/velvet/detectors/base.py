"""Detector framework contract (spec/api-surface.md §5, architecture.md §8).

A detector inspects the core model and returns :class:`Finding` objects.
The framework wraps each finding with the detector's metadata, applies
filtering/triage, deduplicates, sorts and renders it.

Original clean-room implementation.
"""

from __future__ import annotations

import enum
import hashlib
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional, Sequence, Union

if TYPE_CHECKING:
    from velvet.core.compilation_unit import CompilationUnit

logger = logging.getLogger("velvet.detectors")


class Impact(enum.Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"
    OPTIMIZATION = "Optimization"

    @property
    def rank(self) -> int:
        """Ordering rank (higher impact first)."""
        return _IMPACT_ORDER[self]


_IMPACT_ORDER = {
    Impact.HIGH: 0,
    Impact.MEDIUM: 1,
    Impact.LOW: 2,
    Impact.INFORMATIONAL: 3,
    Impact.OPTIMIZATION: 4,
}


class Confidence(enum.Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_ORDER[self]


_CONFIDENCE_ORDER = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}


@dataclass(frozen=True)
class DetectorDocs:
    """Structured documentation block for docs/wiki generation."""

    url: str
    title: str
    description: str
    exploit_scenario: str
    recommendation: str


# ------------------------------------------------------------------ findings
def classify_element(element: Any) -> str:
    """JSON ``type`` of a finding element (architecture.md §10.2)."""
    from velvet.core.cfg_node import CFGNode
    from velvet.core.contract import Contract
    from velvet.core.declarations import Enum, Event, PragmaDirective, Structure
    from velvet.core.function import FunctionLike
    from velvet.core.variables import Variable

    if isinstance(element, Contract):
        return "contract"
    if isinstance(element, FunctionLike):
        return "function"
    if isinstance(element, CFGNode):
        return "node"
    if isinstance(element, PragmaDirective):
        return "pragma"
    if isinstance(element, Enum):
        return "enum"
    if isinstance(element, Structure):
        return "struct"
    if isinstance(element, Event):
        return "event"
    if isinstance(element, Variable):
        return "variable"
    return "other"


def element_name(element: Any) -> str:
    """Human-readable name of a finding element."""
    if isinstance(element, str):
        return element
    name = getattr(element, "canonical_name", None) or getattr(element, "name", None)
    if name:
        return str(name)
    return str(element)


def _element_signature(element: Any) -> str:
    """Normalized, line-number-free signature of an element for stable ids."""
    if isinstance(element, str):
        return f"str:{element}"
    kind = classify_element(element)
    name = element_name(element)
    filename = ""
    source_mapping = getattr(element, "source_mapping", None)
    if source_mapping is not None and source_mapping.filename is not None:
        filename = source_mapping.filename.short
    return f"{kind}:{filename}:{name}"


@dataclass
class Finding:
    """One detector finding: ordered elements + metadata wrapper."""

    elements: list[Any]
    check: str
    impact: Impact
    confidence: Confidence
    title: str = ""
    docs: Optional[DetectorDocs] = None
    additional_fields: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------ rendering
    @property
    def description(self) -> str:
        """Rendered plain-text description (elements joined in order)."""
        return "".join(
            element if isinstance(element, str) else element_name(element)
            for element in self.elements
        )

    @property
    def markdown(self) -> str:
        """Markdown-ish rendering: objects link to their source location."""
        parts: list[str] = []
        for element in self.elements:
            if isinstance(element, str):
                parts.append(element)
            else:
                parts.append(self._markdown_element(element))
        return "".join(parts)

    @staticmethod
    def _markdown_element(element: Any) -> str:
        name = element_name(element)
        source_mapping = getattr(element, "source_mapping", None)
        if source_mapping is None or source_mapping.filename is None:
            return name
        lines = source_mapping.lines
        ref = source_mapping.filename.relative
        if lines:
            ref += f"#L{lines[0]}"
            if len(lines) > 1:
                ref += f"-L{lines[-1]}"
        return f"[{name}]({ref})"

    @property
    def first_markdown_element(self) -> str:
        """The first element rendered standalone (tooling focuses on it)."""
        if not self.elements:
            return ""
        first = self.elements[0]
        if isinstance(first, str):
            return first
        return self._markdown_element(first)

    @property
    def primary_element(self) -> Any:
        """First non-string element (the primary source location)."""
        for element in self.elements:
            if not isinstance(element, str):
                return element
        return self.elements[0] if self.elements else None

    # ------------------------------------------------------------- identity
    @property
    def id(self) -> str:
        """Stable identity hash (rule + normalized element signature).

        Line numbers are deliberately excluded so triage decisions survive
        line-number churn (architecture.md §13.4).
        """
        digest = hashlib.sha256()
        digest.update(self.check.encode())
        for element in self.elements:
            digest.update(_element_signature(element).encode())
        return digest.hexdigest()

    def __str__(self) -> str:
        return self.description


# ------------------------------------------------------------------ detector
class Detector:
    """Base class for detectors (api-surface.md §5.1).

    Subclasses must define the class metadata (``RULE``, ``TITLE``,
    ``IMPACT``, ``CONFIDENCE``, ``DOCS``) and override :meth:`analyze`.
    One instance is created **per compilation unit**.
    """

    RULE: str = ""
    TITLE: str = ""
    IMPACT: Impact = Impact.INFORMATIONAL
    CONFIDENCE: Confidence = Confidence.LOW
    DOCS: DetectorDocs = DetectorDocs(
        url="", title="", description="", exploit_scenario="", recommendation=""
    )

    def __init__(self, compilation_unit: CompilationUnit, session: Any) -> None:
        self.compilation_unit = compilation_unit
        self.session = session
        self.logger = logging.getLogger(f"velvet.detectors.{self.RULE or 'detector'}")
        self.validate_metadata()

    def validate_metadata(self) -> None:
        """Ensure the subclass defines the required metadata (§5.1)."""
        if not self.RULE:
            raise ValueError(f"{type(self).__name__} must define RULE")
        if not self.TITLE:
            raise ValueError(f"{type(self).__name__} must define TITLE")
        if not isinstance(self.IMPACT, Impact):
            raise ValueError(f"{type(self).__name__} must define a valid IMPACT")
        if not isinstance(self.CONFIDENCE, Confidence):
            raise ValueError(f"{type(self).__name__} must define a valid CONFIDENCE")
        if not isinstance(self.DOCS, DetectorDocs):
            raise ValueError(f"{type(self).__name__} must define DOCS")

    # ------------------------------------------------------------- contract
    def analyze(self) -> list[Finding]:
        """Run the detection; must be overridden. Returns findings."""
        raise NotImplementedError

    def finding(
        self,
        elements: Sequence[Union[str, Any]],
        *,
        additional_fields: Optional[dict[str, Any]] = None,
    ) -> Finding:
        """Result builder: interleave human text with model objects.

        The first object element is the primary location (external tooling
        keys off it).
        """
        return Finding(
            elements=list(elements),
            check=self.RULE,
            impact=self.IMPACT,
            confidence=self.CONFIDENCE,
            title=self.TITLE,
            docs=self.DOCS,
            additional_fields=dict(additional_fields or {}),
        )

    # -------------------------------------------------------------- dunder
    def __str__(self) -> str:
        return self.RULE

    def __repr__(self) -> str:
        return f"{type(self).__name__}(rule={self.RULE!r})"
