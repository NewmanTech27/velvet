"""Brownie project adapter. Original clean-room implementation.

Detection: a directory containing ``brownie-config.yaml``.

Strategy: compile the ``contracts/`` tree directly with our own solc
standard-JSON invocation. The pinned solc version and any import remappings
are scraped from the YAML config text with cheap regexes (no YAML
dependency): ``compiler.solc.version`` and ``compiler.solc.remappings``.
Brownie's ethpm packages under ``~/.brownie/packages`` are not auto-fetched;
pass ``include_paths`` if a project needs them.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from velvet.compile.adapters._framework import (
    artifacts_from_solc_output,
    collect_fallback_sources,
    collect_tree_sources,
)
from velvet.compile.adapters.project_dir import _group_by_pragma
from velvet.compile.artifacts import CompilationArtifacts
from velvet.compile.solc_runner import (
    build_standard_json_input,
    run_solc_standard_json,
)
from velvet.compile.versions import select_version
from velvet.exceptions import CompilationError

logger = logging.getLogger("velvet.compile.brownie")

_CONFIG_NAME = "brownie-config.yaml"
_FALLBACK_EXCLUDE = {"build", "reports", "node_modules", ".git"}

_VERSION_RE = re.compile(r"""version\s*:\s*["']?v?(\d+\.\d+\.\d+)["']?""")
_REMAPPINGS_SECTION_RE = re.compile(r"^[ \t]*remappings[ \t]*:[ \t]*([^\n]*)$", re.MULTILINE)
_INLINE_LIST_RE = re.compile(r"\[([^\]]*)\]")
_LIST_ITEM_RE = re.compile(r"""^\s*-\s*["']?([^"'\s]+)["']?\s*$""")


def parse_brownie_config(root: Path) -> dict[str, Any]:
    """Scrape solc version and remappings from brownie-config.yaml."""
    config: dict[str, Any] = {"version": None, "remappings": []}
    path = root / _CONFIG_NAME
    if not path.is_file():
        return config
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return config
    version = _VERSION_RE.search(text)
    if version:
        config["version"] = version.group(1)
    config["remappings"] = _parse_remappings(text)
    return config


def _parse_remappings(text: str) -> list[str]:
    """Extract the ``remappings:`` list (inline ``[..]`` or ``- item`` lines)."""
    section = _REMAPPINGS_SECTION_RE.search(text)
    if not section:
        return []
    inline = _INLINE_LIST_RE.search(section.group(1))
    if inline:
        return re.findall(r"""["']([^"']+)["']""", inline.group(1))
    remaps: list[str] = []
    base_indent = len(section.group(0)) - len(section.group(0).lstrip())
    for line in text[section.end():].splitlines():
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= base_indent and line.strip():
            break
        item = _LIST_ITEM_RE.match(line)
        if item:
            remaps.append(item.group(1))
    return remaps


class BrownieAdapter:
    """Compile a Brownie project (brownie-config.yaml marker)."""

    name = "brownie"

    def matches(self, target: str) -> bool:
        path = Path(target)
        return path.is_dir() and (path / _CONFIG_NAME).is_file()

    def compile(self, target: str, **options: Any) -> list[CompilationArtifacts]:
        root = Path(target).resolve()
        config = parse_brownie_config(root)

        sources = collect_tree_sources(root, ["contracts"])
        if not sources:
            sources = collect_fallback_sources(root, _FALLBACK_EXCLUDE)
        if not sources:
            raise CompilationError(f"No .sol sources found in Brownie project {root}")

        remappings = list(options.get("solc_remaps") or []) or config["remappings"]
        include_paths = [str(p) for p in options.get("include_paths") or []]
        pinned = options.get("solc") or config.get("version")
        results: list[CompilationArtifacts] = []
        for group in _group_by_pragma(sources, pinned):
            results.append(
                self._compile_group(
                    root, group, options, remappings, include_paths, pinned
                )
            )
        return results

    # ------------------------------------------------------------ internals
    def _compile_group(
        self,
        root: Path,
        sources: dict[str, str],
        options: Any,
        remappings: list[str],
        include_paths: list[str],
        pinned: str | None,
    ) -> CompilationArtifacts:
        version = select_version(list(sources.values()), preferred=pinned)
        std_input = build_standard_json_input(
            sources,
            with_abi_bytecode=options.get("with_abi_bytecode", False),
            remappings=remappings or None,
        )
        output = run_solc_standard_json(
            std_input,
            version,
            base_path=str(root),
            include_paths=include_paths or None,
            extra_args=options.get("solc_args"),
        )
        return artifacts_from_solc_output(
            root,
            output,
            sources,
            version=version,
            remappings=remappings,
            include_paths=include_paths,
        )
