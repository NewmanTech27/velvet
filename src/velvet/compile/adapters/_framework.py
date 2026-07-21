"""Shared helpers for framework adapters (foundry/hardhat/brownie).

Original clean-room implementation. These helpers collect source trees,
resolve compiler-reported source names back to disk paths (remapping and
include-path aware) and build normalized CompilationArtifacts from a solc
standard-JSON output.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable

from velvet.compile.artifacts import (
    CompilationArtifacts,
    Filename,
    SourceUnitInfo,
)
from velvet.compile.solc_runner import SolcOutput

logger = logging.getLogger("velvet.compile.framework")


def collect_tree_sources(root: Path, subdirs: Iterable[str]) -> dict[str, str]:
    """Collect {path_relative_to_root: source_text} under each subdir."""
    sources: dict[str, str] = {}
    for sub in subdirs:
        base = root / sub
        if not base.is_dir():
            continue
        for sol in sorted(base.rglob("*.sol")):
            if sol.is_file():
                sources[str(sol.relative_to(root))] = sol.read_text(encoding="utf-8")
    return sources


def collect_fallback_sources(root: Path, exclude: set[str]) -> dict[str, str]:
    """Collect every .sol under root, skipping dependency/build directories.

    Used when a framework's configured sources directory does not exist.
    """
    sources: dict[str, str] = {}
    for sol in sorted(root.rglob("*.sol")):
        parts = set(sol.relative_to(root).parts[:-1])
        if parts & exclude:
            continue
        sources[str(sol.relative_to(root))] = sol.read_text(encoding="utf-8")
    return sources


def split_remapping(remap: str) -> tuple[str, str] | None:
    """Split a solc remapping into (prefix, target).

    Accepts ``prefix=target`` and ``context:prefix=target`` forms.
    """
    body = remap.strip()
    if not body or "=" not in body:
        return None
    prefix, target = body.split("=", 1)
    if ":" in prefix:
        _context, prefix = prefix.split(":", 1)
    if not prefix or not target:
        return None
    return prefix, target


def resolve_source_path(
    root: Path,
    name: str,
    include_paths: Iterable[str] | None = None,
    remappings: Iterable[str] | None = None,
) -> str:
    """Resolve a compiler-reported source name to an absolute disk path.

    The compiler may report a real path relative to the base path
    (``src/Counter.sol``), a virtual import path resolved through an include
    path (``@pkg/contracts/X.sol``), or a remapped virtual path
    (``minilib/MathLib.sol``). Candidates are tried in that order; the final
    fallback is the base-path-relative form even when the file is missing
    (source text then simply stays empty).
    """
    candidates: list[Path] = [root / name]
    for inc in include_paths or ():
        candidates.append(Path(inc) / name)
    for remap in remappings or ():
        parts = split_remapping(remap)
        if parts is None:
            continue
        prefix, target = parts
        if name.startswith(prefix):
            rest = name[len(prefix):]
            candidates.append(root / target / rest)
            candidates.append(Path(target) / rest)
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate.resolve())
    return str((root / name).resolve())


def artifacts_from_solc_output(
    root: Path,
    output: SolcOutput,
    sources: dict[str, str],
    *,
    version: str,
    remappings: Iterable[str] | None = None,
    include_paths: Iterable[str] | None = None,
    working_dir: str | None = None,
) -> CompilationArtifacts:
    """Build normalized artifacts from a solc standard-JSON output."""
    remap_list = list(remappings or ())
    include_list = list(include_paths or ())
    artifacts = CompilationArtifacts(
        compiler_version=version,
        working_dir=str(working_dir) if working_dir is not None else str(root),
    )
    artifacts.remappings = remap_list
    for name, unit in output.sources.items():
        abs_path = resolve_source_path(root, name, include_list, remap_list)
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


def merge_forge_out_artifacts(artifacts: CompilationArtifacts, out_dir: Path) -> None:
    """Merge ABI/bytecode from existing ``out/`` build artifacts.

    Forge writes one JSON per contract as ``out/<File>.sol/<Contract>.json``
    with top-level ``abi`` and ``bytecode``/``deployedBytecode`` objects.
    Missing or malformed files are ignored.
    """
    import json

    if not out_dir.is_dir():
        return
    for artifact_file in sorted(out_dir.rglob("*.json")):
        try:
            doc = json.loads(artifact_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(doc, dict) or "abi" not in doc:
            continue
        name = artifact_file.stem
        artifacts.abis.setdefault(name, doc.get("abi") or [])
        bytecode = doc.get("bytecode") or {}
        deployed = doc.get("deployedBytecode") or {}
        if isinstance(bytecode, dict) or isinstance(deployed, dict):
            artifacts.bytecode.setdefault(
                name,
                {
                    "init": (bytecode or {}).get("object", "")
                    if isinstance(bytecode, dict)
                    else "",
                    "deployed": (deployed or {}).get("object", "")
                    if isinstance(deployed, dict)
                    else "",
                },
            )
