"""Plain directory-of-.sol-files adapter. Original clean-room implementation.

Collects every .sol file under the directory (excluding dependency
directories), compiles them together in one standard-JSON batch. Directories
carrying framework markers (foundry.toml, hardhat.config.*,
brownie-config.yaml) are claimed earlier by the framework adapters in
``velvet.compile``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from velvet.compile.artifacts import (
    CompilationArtifacts,
    Filename,
    SourceUnitInfo,
)
from velvet.compile.solc_runner import (
    build_standard_json_input,
    run_solc_standard_json,
)
from velvet.compile.versions import select_version

logger = logging.getLogger(__name__)

_EXCLUDED_DIRS = {"node_modules", ".git", "out", "cache", "artifacts", "build"}


def _group_by_pragma(
    sources: dict[str, str], preferred: str | None = None
) -> list[dict[str, str]]:
    """Cluster sources into pragma-compatible compilation groups.

    Files with mutually incompatible solidity pragmas cannot share one solc
    invocation; each returned group becomes its own CompilationArtifacts.
    Greedy clustering keeps groups as large as possible. An explicit solc
    override yields a single group (the user takes responsibility).
    """
    if preferred or len(sources) <= 1:
        return [sources]

    from packaging.version import Version

    from velvet.compile.versions import available_versions, parse_pragma

    versions = [Version(v) for v in available_versions()]

    def satisfiable(specs: list) -> bool:
        combined = specs[0]
        for s in specs[1:]:
            combined &= s
        return any(v in combined for v in versions)

    groups: list[tuple[list, dict[str, str]]] = []
    for name in sorted(sources):
        spec = parse_pragma(sources[name])
        placed = False
        for specs, group in groups:
            if satisfiable(specs + [spec]):
                specs.append(spec)
                group[name] = sources[name]
                placed = True
                break
        if not placed:
            groups.append(([spec], {name: sources[name]}))
    return [group for _specs, group in groups]


def collect_sources(root: Path) -> dict[str, str]:
    """Return {relative_path: source_text} for all non-dependency .sol files."""
    sources: dict[str, str] = {}
    for sol in sorted(root.rglob("*.sol")):
        parts = set(sol.relative_to(root).parts[:-1])
        if parts & _EXCLUDED_DIRS:
            continue
        sources[str(sol.relative_to(root))] = sol.read_text(encoding="utf-8")
    return sources


class ProjectDirAdapter:
    """Compile a plain directory tree of .sol files."""

    def matches(self, target: str) -> bool:
        p = Path(target)
        return p.is_dir() and any(p.rglob("*.sol"))

    def compile(self, target: str, **options: Any) -> list[CompilationArtifacts]:
        root = Path(target).resolve()
        sources = collect_sources(root)
        results: list[CompilationArtifacts] = []
        first_error: Exception | None = None
        for group in _group_by_pragma(sources, options.get("solc")):
            try:
                results.append(self._compile_group(root, group, options))
            except Exception as exc:  # degrade, don't crash the whole run
                logger.warning(
                    "Skipping a compilation group (%d file(s)): %s",
                    len(group),
                    str(exc).splitlines()[0] if str(exc) else exc,
                )
                if first_error is None:
                    first_error = exc
        if not results and first_error is not None:
            raise first_error
        return results

    def _compile_group(
        self, root: Path, sources: dict[str, str], options: Any
    ) -> CompilationArtifacts:
        version = select_version(
            list(sources.values()), preferred=options.get("solc")
        )
        std_input = build_standard_json_input(
            sources,
            with_abi_bytecode=options.get("with_abi_bytecode", False),
            remappings=options.get("solc_remaps"),
        )
        include = [str(root / "node_modules")] if (root / "node_modules").is_dir() else None
        output = run_solc_standard_json(
            std_input,
            version,
            base_path=str(root),
            include_paths=include or options.get("include_paths"),
            extra_args=options.get("solc_args"),
        )
        artifacts = CompilationArtifacts(
            compiler_version=version, working_dir=str(root)
        )
        for name, unit in output.sources.items():
            abs_path = str((root / name).resolve())
            src_text = sources.get(name)
            if src_text is None:
                try:
                    src_text = Path(abs_path).read_text(encoding="utf-8")
                except OSError:
                    src_text = ""
            artifacts.source_units[unit["id"]] = SourceUnitInfo(
                source_id=unit["id"],
                filename=Filename(absolute=abs_path, used=name),
                ast=unit["ast"],
                source=src_text,
            )
        for _file, contracts in output.contracts.items():
            for cname, cdata in contracts.items():
                artifacts.abis[cname] = cdata.get("abi", [])
                artifacts.bytecode[cname] = {
                    "init": cdata.get("evm", {}).get("bytecode", {}).get("object", ""),
                    "deployed": cdata.get("evm", {})
                    .get("deployedBytecode", {})
                    .get("object", ""),
                }
        return artifacts
