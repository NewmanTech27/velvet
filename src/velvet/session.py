"""Velvet session — pipeline orchestration + plugin registries.

``Velvet(target, **options)`` runs the full pipeline at construction
(spec/api-surface.md §2): compile -> parse -> IR -> SSA -> built-in
analyses, all cached.  Detectors and printers are then registered and run
against the immutable-ish model.

Original clean-room implementation.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from velvet.compile import compile_target
from velvet.core.compilation_unit import CompilationUnit
from velvet.core.contract import Contract
from velvet.detectors.base import Detector, Finding, Impact
from velvet.parsing import parse_artifacts
from velvet.printers.base import Printer

logger = logging.getLogger("velvet.session")

# Options forwarded to the compilation layer; everything else is session-level.
_COMPILE_OPTION_KEYS = (
    "solc",
    "solc_args",
    "solc_remaps",
    "include_paths",
    "with_abi_bytecode",
    "force_framework",
    "ignore_compile",
    "explorer_network",
    "explorer_api_key",
)


class Velvet:
    """Root analysis object / session entry point (alias: ``Analyzer``)."""

    def __init__(self, target: Any, **options: Any) -> None:
        self.target = target
        self.options = dict(options)
        # filtering/triage options (framework-level, consumed by filtering.py)
        self.filter_paths: list[str] = _as_list(options.get("filter_paths"))
        self.include_paths: list[str] = _as_list(options.get("include_paths"))
        self.exclude_dependencies: bool = bool(options.get("exclude_dependencies", False))
        self.triage_mode: bool = bool(options.get("triage_mode", False))
        self.triage_database: str = options.get("triage_database", "velvet.db.json")
        self.show_ignored_findings: bool = bool(options.get("show_ignored_findings", False))
        self.generate_patches: bool = bool(options.get("generate_patches", False))
        # SARIF triage workflow (§10.3): import triage state from a SARIF file
        self.sarif_input: str = options.get("sarif_input", "")
        self.no_fail: bool = bool(options.get("no_fail", False))
        self.disable_color: bool = bool(options.get("disable_color", False))
        self.change_line_prefix: str = options.get("change_line_prefix", "#")
        self.markdown_root: str = options.get("markdown_root", "")
        self.export_dir: str = options.get("export_dir", ".")

        self._compilation_units: list[CompilationUnit] = []
        self._detectors: list[type[Detector]] = []
        self._printers: list[type[Printer]] = []
        self._printer_sink: list[str] = []

        self._run_pipeline(target, options)
        self._register_builtin_plugins()

    # ------------------------------------------------------------ pipeline
    def _run_pipeline(self, target: Any, options: dict[str, Any]) -> None:
        from velvet.ir.convert import convert_unit
        from velvet.ir.ssa import convert_unit_ssa
        from velvet.analyses.read_write import function_read_write

        if isinstance(target, CompilationUnit):
            units = [target]
        else:
            compile_options = {
                k: v for k, v in options.items() if k in _COMPILE_OPTION_KEYS
            }
            artifacts_list = compile_target(str(target), **compile_options)
            units = []
            for artifacts in artifacts_list:
                try:
                    units.append(
                        parse_artifacts(
                            artifacts, skip_assembly=options.get("skip_assembly", True)
                        )
                    )
                except Exception:  # noqa: BLE001 - per-unit degradation (§12)
                    logger.exception("Failed to parse a compilation unit; skipping")
                    if not options.get("no_fail", False):
                        raise
        for unit in units:
            convert_unit(unit)
            convert_unit_ssa(unit)
            # Pre-warm shared analyses (they are also lazily cached).
            for function in unit.functions_and_modifiers:
                try:
                    function_read_write(function)
                except Exception:  # noqa: BLE001
                    logger.debug(
                        "read/write analysis failed for %s",
                        function.canonical_name,
                        exc_info=True,
                    )
        self._compilation_units = units

    # ------------------------------------------------------------ traversal
    @property
    def compilation_units(self) -> list[CompilationUnit]:
        return self._compilation_units

    @property
    def contracts(self) -> list[Contract]:
        return [c for unit in self._compilation_units for c in unit.contracts]

    @property
    def contracts_derived(self) -> list[Contract]:
        return [c for unit in self._compilation_units for c in unit.contracts_derived]

    def get_contract_from_name(self, name: str) -> Optional[Contract] | list[Contract]:
        matches = [c for c in self.contracts if c.name == name]
        if not matches:
            return None
        if len(matches) == 1:
            return matches[0]
        return matches

    def filename_lookup(self, path: str) -> Any:
        for unit in self._compilation_units:
            found = unit.filename_lookup(path)
            if found is not None:
                return found
        return None

    def source_code(self, path: str) -> str:
        for unit in self._compilation_units:
            for info in unit.compilation.source_units.values():
                f = info.filename
                if path in (f.used, f.absolute, f.relative, f.short):
                    return info.source
        return ""

    # ------------------------------------------------------------ registries
    def _register_builtin_plugins(self) -> None:
        from velvet.detectors import BUILTIN_DETECTORS
        from velvet.printers import BUILTIN_PRINTERS

        for cls in BUILTIN_DETECTORS:
            self.register_detector(cls)
        for cls in BUILTIN_PRINTERS:
            self.register_printer(cls)
        self._register_entry_point_plugins()

    def _register_entry_point_plugins(self) -> None:
        """Auto-register third-party plugins advertised via entry points."""
        try:
            from importlib.metadata import entry_points
        except ImportError:  # pragma: no cover - py<3.10 fallback
            return
        for group, register in (
            ("velvet.detectors", self.register_detector),
            ("velvet.printers", self.register_printer),
        ):
            try:
                discovered = entry_points(group=group)
            except TypeError:  # pragma: no cover - old importlib.metadata API
                discovered = entry_points().get(group, [])
            for entry in discovered:
                try:
                    register(entry.load())
                except Exception:  # noqa: BLE001 - bad plugin must not crash
                    logger.warning("Failed to load plugin %s", entry, exc_info=True)

    def register_detector(self, detector_class: type[Detector]) -> None:
        for registered in self._detectors:
            if registered.RULE == detector_class.RULE:
                if registered is detector_class:
                    return  # idempotent re-registration of the same class
                raise ValueError(
                    f"A detector with rule {detector_class.RULE!r} is already registered"
                )
        self._detectors.append(detector_class)

    def unregister_detector(self, detector_class: type[Detector]) -> None:
        self._detectors = [d for d in self._detectors if d is not detector_class]

    def register_printer(self, printer_class: type[Printer]) -> None:
        if any(p.RULE == printer_class.RULE for p in self._printers):
            raise ValueError(
                f"A printer with rule {printer_class.RULE!r} is already registered"
            )
        self._printers.append(printer_class)

    def unregister_printer(self, printer_class: type[Printer]) -> None:
        self._printers = [p for p in self._printers if p is not printer_class]

    @property
    def registered_detectors(self) -> list[type[Detector]]:
        return list(self._detectors)

    @property
    def registered_printers(self) -> list[type[Printer]]:
        return list(self._printers)

    def _detectors_by_impact(self, impact: Impact) -> list[type[Detector]]:
        return [d for d in self._detectors if d.IMPACT == impact]

    @property
    def detectors_high(self) -> list[type[Detector]]:
        return self._detectors_by_impact(Impact.HIGH)

    @property
    def detectors_medium(self) -> list[type[Detector]]:
        return self._detectors_by_impact(Impact.MEDIUM)

    @property
    def detectors_low(self) -> list[type[Detector]]:
        return self._detectors_by_impact(Impact.LOW)

    @property
    def detectors_informational(self) -> list[type[Detector]]:
        return self._detectors_by_impact(Impact.INFORMATIONAL)

    @property
    def detectors_optimization(self) -> list[type[Detector]]:
        return self._detectors_by_impact(Impact.OPTIMIZATION)

    # --------------------------------------------------------------- running
    def run_detectors(self) -> list[Finding]:
        """Run all registered detectors, filter/triage, dedup and sort."""
        findings: list[Finding] = []
        for detector_class in sorted(self._detectors, key=lambda d: d.RULE):
            for unit in self._compilation_units:
                try:
                    detector = detector_class(unit, self)
                    findings.extend(detector.analyze())
                except Exception:  # noqa: BLE001 - a detector must not crash the run
                    logger.exception("Detector %s failed", detector_class.RULE)
        findings = [f for f in findings if self.valid_result(f)]
        # dedup by stable identity, keep first occurrence (deterministic)
        seen: set[str] = set()
        unique: list[Finding] = []
        for finding in findings:
            if finding.id not in seen:
                seen.add(finding.id)
                unique.append(finding)
        unique.sort(
            key=lambda f: (
                f.impact.rank,
                f.confidence.rank,
                f.check,
                f.description,
            )
        )
        # triage is the last filtering stage (architecture.md §11): in triage
        # mode this lists findings and prompts interactively; then the triage
        # database hides recorded findings (unless show_ignored_findings).
        from velvet.triage import apply_triage

        return apply_triage(self, unique)

    def run_printers(self) -> list[str]:
        """Run all registered printers; returns the captured console text."""
        self._printer_sink = []
        for printer_class in sorted(self._printers, key=lambda p: p.RULE):
            for unit in self._compilation_units:
                try:
                    printer = printer_class(unit, self)
                    printer.output()
                except Exception:  # noqa: BLE001
                    logger.exception("Printer %s failed", printer_class.RULE)
        return list(self._printer_sink)

    def printer_output_sink(self, text: str) -> None:
        self._printer_sink.append(text)

    # -------------------------------------------------------------- filtering
    def valid_result(self, finding: Finding) -> bool:
        """Framework-level filtering: path filters, dependency exclusion and
        inline suppressions (detectors never see suppressed findings)."""
        from velvet.filtering import result_in_scope

        return result_in_scope(self, finding)

    def __str__(self) -> str:
        return f"Velvet({self.target!r})"


#: Ergonomic alias (api-surface.md §2).
Analyzer = Velvet


def _as_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)
