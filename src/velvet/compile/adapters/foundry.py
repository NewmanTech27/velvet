"""Foundry project adapter. Original clean-room implementation.

Detection: a directory containing ``foundry.toml``.

Strategy (per spec/architecture.md §3.1: use the framework pipeline when
possible, fall back to direct solc with parsed configuration):

1. Unless ``ignore_compile`` is set and a ``forge`` binary is available, run
   ``forge build --extra-output abi evm.bytecode evm.deployedBytecode`` so
   git-submodule dependencies are synced and ``out/`` artifacts are fresh.
   A missing ``forge`` binary or a failing build never aborts the run — the
   authoritative compilation is always step 2.
2. Compile the project's ``src`` tree ourselves through solc standard-JSON,
   honoring the remappings declared in ``foundry.toml`` and/or
   ``remappings.txt`` (passed into the standard-JSON settings). Files under
   ``lib/`` are pulled in through those remappings and are flagged as
   dependencies by the usual path rules.
3. When ``ignore_compile`` is set, existing ``out/`` artifacts are merged in
   for ABI/bytecode (the AST still comes from our own solc run).
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from velvet.compile.adapters._framework import (
    artifacts_from_solc_output,
    collect_fallback_sources,
    collect_tree_sources,
    merge_forge_out_artifacts,
)
from velvet.compile.adapters.project_dir import _group_by_pragma
from velvet.compile.artifacts import CompilationArtifacts
from velvet.compile.solc_runner import (
    build_standard_json_input,
    run_solc_standard_json,
)
from velvet.compile.versions import select_version
from velvet.exceptions import CompilationError

logger = logging.getLogger("velvet.compile.foundry")

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    tomllib = None  # type: ignore[assignment]

_FALLBACK_EXCLUDE = {"lib", "out", "cache", "node_modules", ".git", "broadcast"}

_QUOTED = r"""["']([^"']+)["']"""


def _scalar(text: str, key: str) -> str | None:
    """Regex fallback for ``key = "value"`` inside foundry.toml."""
    pattern = r"^\s*" + re.escape(key) + r"\s*=\s*" + _QUOTED
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1) if match else None


def _string_array(text: str, key: str) -> list[str]:
    """Regex fallback for ``key = ["a", "b"]`` inside foundry.toml."""
    pattern = r"^\s*" + re.escape(key) + r"\s*=\s*\[([^\]]*)\]"
    match = re.search(pattern, text, re.MULTILINE | re.DOTALL)
    if not match:
        return []
    return re.findall(_QUOTED, match.group(1))


def parse_foundry_config(root: Path) -> dict[str, Any]:
    """Parse the bits of foundry.toml we need (profile.default section)."""
    config: dict[str, Any] = {
        "src": "src",
        "out": "out",
        "solc_version": None,
        "remappings": [],
    }
    path = root / "foundry.toml"
    if not path.is_file():
        return config
    text = path.read_text(encoding="utf-8")
    profile: dict[str, Any] | None = None
    if tomllib is not None:
        try:
            doc = tomllib.loads(text)
            profile = doc.get("profile", {}).get("default", {})
        except Exception:  # noqa: BLE001 - tolerate malformed toml
            profile = None
    if profile:
        config["src"] = profile.get("src", config["src"])
        config["out"] = profile.get("out", config["out"])
        config["solc_version"] = profile.get("solc_version") or profile.get("solc")
        config["remappings"] = list(profile.get("remappings") or [])
    else:  # minimal regex fallback (also used for malformed toml)
        config["src"] = _scalar(text, "src") or config["src"]
        config["out"] = _scalar(text, "out") or config["out"]
        config["solc_version"] = _scalar(text, "solc_version") or _scalar(text, "solc")
        config["remappings"] = _string_array(text, "remappings")
    return config


def parse_remappings_txt(root: Path) -> list[str]:
    """Read remappings.txt (one ``prefix=target`` per line, # comments)."""
    path = root / "remappings.txt"
    if not path.is_file():
        return []
    remaps: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if line and "=" in line:
            remaps.append(line)
    return remaps


def gather_remappings(root: Path, config: dict[str, Any]) -> list[str]:
    """foundry.toml remappings plus remappings.txt, deduped, order kept."""
    seen: set[str] = set()
    merged: list[str] = []
    for remap in [*parse_remappings_txt(root), *config.get("remappings", [])]:
        if remap not in seen:
            seen.add(remap)
            merged.append(remap)
    return merged


class FoundryAdapter:
    """Compile a Foundry project (foundry.toml marker)."""

    name = "foundry"

    def matches(self, target: str) -> bool:
        path = Path(target)
        return path.is_dir() and (path / "foundry.toml").is_file()

    def compile(self, target: str, **options: Any) -> list[CompilationArtifacts]:
        root = Path(target).resolve()
        config = parse_foundry_config(root)
        remappings = list(options.get("solc_remaps") or []) or gather_remappings(
            root, config
        )
        ignore_compile = bool(options.get("ignore_compile", False))

        if not ignore_compile:
            self._forge_build(root)

        sources = collect_tree_sources(root, [config["src"]])
        if not sources:
            sources = collect_fallback_sources(root, _FALLBACK_EXCLUDE)
        if not sources:
            raise CompilationError(f"No .sol sources found in Foundry project {root}")

        pinned = options.get("solc") or config.get("solc_version")
        results: list[CompilationArtifacts] = []
        for group in _group_by_pragma(sources, pinned):
            results.append(
                self._compile_group(root, group, options, remappings, pinned)
            )
        if ignore_compile:
            for artifacts in results:
                merge_forge_out_artifacts(artifacts, root / config["out"])
        return results

    # ------------------------------------------------------------ internals
    def _forge_build(self, root: Path) -> None:
        """Best-effort ``forge build`` pre-step (skipped when forge absent)."""
        forge = shutil.which("forge")
        if forge is None:
            logger.info(
                "forge binary not found; falling back to direct solc compilation"
            )
            return
        try:
            proc = subprocess.run(
                [
                    forge,
                    "build",
                    "--extra-output",
                    "abi",
                    "evm.bytecode",
                    "evm.deployedBytecode",
                ],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=600,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("forge build could not run (%s); using direct solc", exc)
            return
        if proc.returncode != 0:
            logger.warning(
                "forge build failed; continuing with direct solc compilation:\n%s",
                (proc.stderr or proc.stdout or "").strip()[:2000],
            )

    def _compile_group(
        self,
        root: Path,
        sources: dict[str, str],
        options: Any,
        remappings: list[str],
        pinned: str | None,
    ) -> CompilationArtifacts:
        version = select_version(list(sources.values()), preferred=pinned)
        std_input = build_standard_json_input(
            sources,
            with_abi_bytecode=options.get("with_abi_bytecode", False),
            remappings=remappings or None,
        )
        include_paths = list(options.get("include_paths") or [])
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
