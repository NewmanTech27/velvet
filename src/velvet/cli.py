"""velvet command-line interface (spec/api-surface.md §7, v1 subset).

``velvet target [--detect a,b] [--exclude a,b] [--exclude-<impact>]
[--list-detectors] [--print a,b] [--list-printers] [--json FILE|-]
[--json-types ...] [--sarif FILE] [--sarif-input FILE] [--sarif-triage FILE]
[--disable-color] [--filter-paths P] [--include-paths P]
[--exclude-dependencies] [--triage-mode] [--triage-database FILE]
[--show-ignored-findings] [--checklist] [--markdown-root URL]
[--checklist-limit N] [--wiki DIR] [--zip FILE] [--zip-type lzma|zlib|stored]
[--generate-patches] [--patches-dir DIR]
[--fail-on pedantic|low|medium|high|none] [--solc BIN] ...``

``velvet.config.json`` is auto-loaded from the current directory; CLI
flags always win over configuration values.

Original clean-room implementation.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Optional

import velvet
from velvet.detectors import BUILTIN_DETECTORS
from velvet.detectors.base import Detector
from velvet.exceptions import VelvetError
from velvet.filtering import should_fail
from velvet.printers import BUILTIN_PRINTERS
from velvet.session import Velvet

logger = logging.getLogger("velvet.cli")

_FAIL_ON_CHOICES = ("pedantic", "low", "medium", "high", "none")
_EXCLUDABLE_IMPACTS = ("informational", "optimization", "low", "medium", "high")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="velvet",
        description="velvet — a clean-room static analysis framework for Solidity.",
    )
    parser.add_argument("target", nargs="?", help=".sol file, directory or standard-JSON")
    parser.add_argument("--version", action="version", version=f"velvet {velvet.__version__}")
    # analysis selection
    parser.add_argument("--detect", metavar="RULES", help="comma-separated detector rules to run")
    parser.add_argument("--exclude", metavar="RULES", help="comma-separated detector rules to skip")
    for impact in _EXCLUDABLE_IMPACTS:
        parser.add_argument(
            f"--exclude-{impact}",
            action="store_true",
            help=f"exclude {impact}-impact detectors",
        )
    parser.add_argument("--exclude-dependencies", action="store_true", default=None)
    parser.add_argument("--list-detectors", action="store_true")
    parser.add_argument("--print", dest="printers", metavar="PRINTERS", help="comma-separated printers to run")
    parser.add_argument("--list-printers", action="store_true")
    # output
    parser.add_argument("--json", metavar="FILE", help="write JSON output (use - for stdout)")
    parser.add_argument("--json-types", metavar="TYPES", help="comma-separated JSON sections")
    parser.add_argument("--sarif", metavar="FILE", help="write SARIF v2.1.0 output")
    parser.add_argument(
        "--sarif-input",
        metavar="FILE",
        default=None,
        help="import triage state from an existing SARIF file "
        "(suppressed/baselined results are hidden)",
    )
    parser.add_argument(
        "--sarif-triage",
        metavar="FILE",
        default=None,
        help="export a triage SARIF whose results include the suppression state",
    )
    parser.add_argument(
        "--generate-patches",
        action="store_true",
        default=None,
        help="attach machine-applicable patches to findings in JSON output",
    )
    parser.add_argument(
        "--patches-dir",
        metavar="DIR",
        default=None,
        help="also write unified-diff .patch files to DIR (implies --generate-patches)",
    )
    parser.add_argument(
        "--wiki",
        metavar="DIR",
        default=None,
        help="render the detector documentation wiki pages to DIR",
    )
    parser.add_argument(
        "--zip",
        dest="zip_file",
        metavar="FILE",
        default=None,
        help="bundle the full JSON results into a compressed zip archive",
    )
    parser.add_argument(
        "--zip-type",
        choices=("lzma", "zlib", "stored"),
        default=None,
        help="zip compression for --zip (default: lzma)",
    )
    parser.add_argument("--disable-color", action="store_true", default=None)
    parser.add_argument("--change-line-prefix", metavar="PREFIX", default=None)
    # filtering & policy
    parser.add_argument("--filter-paths", metavar="PATTERNS", help="comma-separated path filters")
    parser.add_argument("--include-paths", metavar="PATTERNS", help="comma-separated path inclusions")
    parser.add_argument("--fail-on", choices=_FAIL_ON_CHOICES, default=None)
    # triage (architecture.md §11)
    parser.add_argument(
        "--triage-mode",
        action="store_true",
        default=None,
        help="interactively select findings to hide during next runs",
    )
    parser.add_argument(
        "--triage-database",
        metavar="FILE",
        default=None,
        help="triage database path (default: velvet.db.json)",
    )
    parser.add_argument(
        "--show-ignored-findings",
        action="store_true",
        default=None,
        help="reveal findings hidden by the triage database (marked as hidden)",
    )
    # markdown checklist (architecture.md §10.4)
    parser.add_argument(
        "--checklist",
        action="store_true",
        default=None,
        help="print a markdown checklist report to stdout",
    )
    parser.add_argument(
        "--markdown-root",
        metavar="URL",
        default=None,
        help="repository URL prefix for checklist source links (normalized to .../blob/<ref>/)",
    )
    parser.add_argument(
        "--checklist-limit",
        metavar="N",
        type=int,
        default=None,
        help="maximum number of checklist items per rule",
    )
    # compilation pass-through
    parser.add_argument("--solc", metavar="BIN_OR_VERSION", default=None)
    parser.add_argument("--solc-args", metavar="ARGS", default=None)
    parser.add_argument("--solc-remaps", metavar="REMAPS", default=None)
    parser.add_argument("--force-framework", metavar="NAME", default=None)
    parser.add_argument("--etherscan-apikey", metavar="KEY", default=None)
    parser.add_argument("--explorer-network", metavar="NAME", default=None)
    parser.add_argument("--skip-assembly", action="store_true", default=None)
    parser.add_argument("--no-fail", action="store_true", default=None)
    parser.add_argument("--config-file", metavar="FILE", default=None)
    parser.add_argument("--log-level", metavar="LEVEL", default=None)
    return parser


# ------------------------------------------------------------ configuration
def load_config(config_file: Optional[str]) -> dict[str, Any]:
    path = Path(config_file) if config_file else Path("velvet.config.json")
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Ignoring unreadable config %s: %s", path, exc)
        return {}


def _split_csv(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def _pick(cli_value: Any, config: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """CLI wins; then the first present config key; then default."""
    if cli_value not in (None, [], False):
        return cli_value
    for key in keys:
        if key in config:
            return config[key]
    return default


# ------------------------------------------------------------------ listing
def _print_detector_table(detector_classes: list[type[Detector]]) -> None:
    rows = sorted(
        ((d.RULE, d.TITLE, d.IMPACT.value, d.CONFIDENCE.value) for d in detector_classes),
        key=lambda r: r[0],
    )
    print(f"{'Rule':<28} {'Impact':<14} {'Confidence':<12} Title")
    for rule, title, impact, confidence in rows:
        print(f"{rule:<28} {impact:<14} {confidence:<12} {title}")


def _print_printer_table(printer_classes: list[type]) -> None:
    rows = sorted(((p.RULE, p.TITLE) for p in printer_classes), key=lambda r: r[0])
    print(f"{'Printer':<28} Title")
    for rule, title in rows:
        print(f"{rule:<28} {title}")


# -------------------------------------------------------------------- main
def _select_detectors(session: Velvet, args: argparse.Namespace, config: dict[str, Any]) -> None:
    """Apply --detect/--exclude/--exclude-<impact> to the registry."""
    detect = set(_split_csv(_pick(args.detect, config, "detectors_to_run")))
    exclude = set(_split_csv(_pick(args.exclude, config, "detectors_to_exclude")))
    excluded_impacts = {
        impact.upper()
        for impact in _EXCLUDABLE_IMPACTS
        if _pick(getattr(args, f"exclude_{impact}"), config, f"exclude_{impact}", default=False)
    }
    for detector_class in list(session.registered_detectors):
        keep = True
        if detect and detector_class.RULE not in detect:
            keep = False
        if detector_class.RULE in exclude:
            keep = False
        if detector_class.IMPACT.name in excluded_impacts:
            keep = False
        if not keep:
            session.unregister_detector(detector_class)


def _select_printers(session: Velvet, args: argparse.Namespace, config: dict[str, Any]) -> None:
    requested = set(_split_csv(_pick(args.printers, config, "printers_to_run")))
    for printer_class in list(session.registered_printers):
        if printer_class.RULE not in requested:
            session.unregister_printer(printer_class)


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=getattr(logging, (args.log_level or "WARNING").upper()))
    config = load_config(args.config_file)

    # Listings do not require a target/compilation.
    if args.list_detectors:
        _print_detector_table(BUILTIN_DETECTORS)
        return 0
    if args.list_printers:
        _print_printer_table(BUILTIN_PRINTERS)
        return 0

    # The documentation wiki only needs detector metadata: no target required.
    wiki_dir = _pick(args.wiki, config, "wiki")
    if wiki_dir and not args.target:
        from velvet.outputs.wiki import write_wiki

        written = write_wiki(list(BUILTIN_DETECTORS), wiki_dir)
        print(f"Wrote {len(written)} detector documentation pages to {wiki_dir}")
        return 0
    if not args.target:
        build_parser().error("a target is required (or use --list-detectors)")

    disable_color = bool(_pick(args.disable_color, config, "disable_color", default=False))
    session_options: dict[str, Any] = {
        "solc": _pick(args.solc, config, "solc"),
        "solc_args": _split_csv(_pick(args.solc_args, config, "solc_args")),
        "solc_remaps": _split_csv(_pick(args.solc_remaps, config, "solc_remaps")),
        "filter_paths": _split_csv(_pick(args.filter_paths, config, "filter_paths")),
        "include_paths": _split_csv(_pick(args.include_paths, config, "include_paths")),
        "exclude_dependencies": bool(
            _pick(args.exclude_dependencies, config, "exclude_dependencies", default=False)
        ),
        "skip_assembly": bool(_pick(args.skip_assembly, config, "skip_assembly", default=True)),
        "no_fail": bool(_pick(args.no_fail, config, "no_fail", default=False)),
        "disable_color": disable_color,
        "change_line_prefix": _pick(
            args.change_line_prefix, config, "change_line_prefix", default="#"
        ),
        # triage (§11) & markdown report (§10.4)
        "triage_mode": bool(_pick(args.triage_mode, config, "triage_mode", default=False)),
        "triage_database": _pick(args.triage_database, config, "triage_database"),
        "show_ignored_findings": bool(
            _pick(args.show_ignored_findings, config, "show_ignored_findings", default=False)
        ),
        "markdown_root": _pick(args.markdown_root, config, "markdown_root"),
        # patches (§10.5) & SARIF triage workflow (§10.3)
        "generate_patches": bool(
            _pick(args.generate_patches, config, "generate_patches", default=False)
        )
        or bool(_pick(args.patches_dir, config, "patches_dir")),
        "sarif_input": _pick(args.sarif_input, config, "sarif_input"),
        # compilation/framework pass-through (consumed by the compile layer)
        "force_framework": _pick(args.force_framework, config, "force_framework"),
        "etherscan_apikey": _pick(args.etherscan_apikey, config, "etherscan_apikey"),
        "explorer_network": _pick(args.explorer_network, config, "explorer_network"),
    }
    session_options = {k: v for k, v in session_options.items() if v not in (None, [])}

    try:
        session = Velvet(args.target, **session_options)
    except VelvetError as exc:
        print(f"velvet: {exc}", file=sys.stderr)
        return 2

    _select_detectors(session, args, config)
    _select_printers(session, args, config)

    # The SARIF triage export must carry suppression state, so hidden
    # findings are kept (marked) for it; every other output stays visible-only.
    sarif_triage_target = _pick(args.sarif_triage, config, "sarif_triage")
    reveal_for_triage_export = bool(sarif_triage_target) and not session.show_ignored_findings
    if reveal_for_triage_export:
        session.show_ignored_findings = True

    try:
        findings = session.run_detectors()
    except VelvetError as exc:  # e.g. --triage-mode without an interactive stdin
        print(f"velvet: {exc}", file=sys.stderr)
        return 2
    visible_findings = (
        [f for f in findings if not getattr(f, "hidden", False)]
        if reveal_for_triage_export
        else findings
    )
    printer_results = session.run_printers() if session.registered_printers else []

    # console rendering (suppressed when JSON goes to stdout)
    json_target = _pick(args.json, config, "json")
    from velvet.outputs.console import render_findings_console

    console_text = render_findings_console(
        visible_findings,
        disable_color=disable_color,
        line_prefix=session.change_line_prefix,
    )
    if console_text and json_target != "-":
        print(console_text)
    if printer_results:
        print("\n".join(printer_results))

    # markdown checklist report (architecture.md §10.4); like the console
    # text it is suppressed when JSON goes to stdout
    if bool(_pick(args.checklist, config, "checklist", default=False)) and json_target != "-":
        from velvet.outputs.checklist import render_checklist

        checklist_limit = _pick(args.checklist_limit, config, "checklist_limit")
        print(
            render_checklist(
                visible_findings,
                markdown_root=session.markdown_root,
                limit=None if checklist_limit is None else int(checklist_limit),
            ),
            end="",
        )

    # machine outputs
    if json_target:
        from velvet.outputs.json_out import build_json_output, dump_json

        json_types = _split_csv(_pick(args.json_types, config, "json-types"))
        document = build_json_output(
            session,
            visible_findings,
            printer_results=printer_results,
            json_types=json_types or None,
            console_text=console_text,
        )
        text = dump_json(document)
        if json_target == "-":
            sys.stdout.write(text)
        else:
            Path(json_target).write_text(text)
            logger.info("JSON written to %s", json_target)

    # machine-applicable patch diffs (§10.5; implies --generate-patches)
    patches_dir = _pick(args.patches_dir, config, "patches_dir")
    if patches_dir:
        from velvet.outputs.patches import write_patch_files

        written = write_patch_files(session, visible_findings, patches_dir)
        logger.info("Wrote %d patch file(s) to %s", len(written), patches_dir)

    sarif_target = _pick(args.sarif, config, "sarif")
    if sarif_target:
        from velvet.outputs.sarif import build_sarif

        Path(sarif_target).write_text(json.dumps(build_sarif(session, visible_findings), indent=2) + "\n")
        logger.info("SARIF written to %s", sarif_target)

    if sarif_triage_target:
        from velvet.outputs.sarif import build_sarif

        triage_sarif = build_sarif(session, findings, triage=True)
        Path(sarif_triage_target).write_text(json.dumps(triage_sarif, indent=2) + "\n")
        logger.info("SARIF triage export written to %s", sarif_triage_target)

    # detector documentation wiki (§10.4), alongside an analysis run
    if wiki_dir:
        from velvet.outputs.wiki import write_wiki

        written = write_wiki(session.registered_detectors, wiki_dir)
        logger.info("Wrote %d wiki pages to %s", len(written), wiki_dir)

    # zip results bundle (§10.4)
    zip_target = _pick(args.zip_file, config, "zip")
    if zip_target:
        from velvet.outputs.zip_export import DEFAULT_ZIP_TYPE, write_zip_export

        zip_type = _pick(args.zip_type, config, "zip_type", default=DEFAULT_ZIP_TYPE)
        write_zip_export(
            session,
            visible_findings,
            zip_target,
            zip_type=zip_type,
            printer_results=printer_results,
            console_text=console_text,
        )
        logger.info("Results bundle written to %s", zip_target)

    fail_on = _pick(args.fail_on, config, "fail_on", default="none")
    return 1 if should_fail(visible_findings, fail_on) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
