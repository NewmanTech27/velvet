"""Hardhat project adapter. Original clean-room implementation.

Detection: a directory containing ``hardhat.config.js`` or
``hardhat.config.ts``.

Strategy: compile the ``contracts/`` tree directly with our own solc
standard-JSON invocation. The configured solc version is scraped from the
config file text with a cheap regex (no JS evaluation); ``node_modules`` is
passed as an include path so ``@openzeppelin/...``-style imports resolve and
anything under it is flagged as a dependency. When an ``npx`` binary exists
and ``ignore_compile`` is not set, a best-effort ``npx --no-install hardhat
compile`` pre-step is attempted first (``--no-install`` keeps it offline and
fast when hardhat is not actually installed); failure never aborts the run —
our solc compilation is authoritative.
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
)
from velvet.compile.adapters.project_dir import _group_by_pragma
from velvet.compile.artifacts import CompilationArtifacts
from velvet.compile.solc_runner import (
    build_standard_json_input,
    run_solc_standard_json,
)
from velvet.compile.versions import select_version
from velvet.exceptions import CompilationError

logger = logging.getLogger("velvet.compile.hardhat")

_CONFIG_NAMES = ("hardhat.config.js", "hardhat.config.ts")
_FALLBACK_EXCLUDE = {"node_modules", "artifacts", "cache", ".git", "typechain-types"}

_VERSION_RE = re.compile(r"""version\s*:\s*["'](\d+\.\d+\.\d+)["']""")
_SOLIDITY_SHORTHAND_RE = re.compile(r"""solidity\s*:\s*["'](\d+\.\d+\.\d+)["']""")
_SOURCES_PATH_RE = re.compile(r"""sources\s*:\s*["']([^"']+)["']""")


def find_config(root: Path) -> Path | None:
    """Return the hardhat config file, preferring .js over .ts."""
    for name in _CONFIG_NAMES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def parse_hardhat_config(root: Path) -> dict[str, Any]:
    """Scrape solc version and sources path from the config text.

    Cheap regex extraction only — the JS/TS config is never evaluated.
    Supports ``solidity: {version: "0.8.24"}``, multi-compiler
    ``solidity: {compilers: [{version: ...}]}`` (first entry wins) and the
    ``solidity: "0.8.24"`` shorthand.
    """
    config: dict[str, Any] = {"version": None, "sources": "contracts"}
    path = find_config(root)
    if path is None:
        return config
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return config
    shorthand = _SOLIDITY_SHORTHAND_RE.search(text)
    version = _VERSION_RE.search(text)
    if shorthand:
        config["version"] = shorthand.group(1)
    elif version:
        config["version"] = version.group(1)
    sources = _SOURCES_PATH_RE.search(text)
    if sources:
        config["sources"] = sources.group(1)
    return config


class HardhatAdapter:
    """Compile a Hardhat project (hardhat.config.js/ts marker)."""

    name = "hardhat"

    def matches(self, target: str) -> bool:
        path = Path(target)
        return path.is_dir() and find_config(path) is not None

    def compile(self, target: str, **options: Any) -> list[CompilationArtifacts]:
        root = Path(target).resolve()
        config = parse_hardhat_config(root)
        if not options.get("ignore_compile", False):
            self._npx_hardhat_compile(root)

        sources_dir = config["sources"]
        sources = collect_tree_sources(root, [sources_dir])
        if not sources:
            sources = collect_fallback_sources(root, _FALLBACK_EXCLUDE)
        if not sources:
            raise CompilationError(f"No .sol sources found in Hardhat project {root}")

        include_paths: list[str] = []
        node_modules = root / "node_modules"
        if node_modules.is_dir():
            include_paths.append(str(node_modules))
        include_paths.extend(str(p) for p in options.get("include_paths") or [])

        pinned = options.get("solc") or config.get("version")
        results: list[CompilationArtifacts] = []
        for group in _group_by_pragma(sources, pinned):
            results.append(
                self._compile_group(root, group, options, include_paths, pinned)
            )
        return results

    # ------------------------------------------------------------ internals
    def _npx_hardhat_compile(self, root: Path) -> None:
        """Best-effort ``npx --no-install hardhat compile`` pre-step."""
        npx = shutil.which("npx")
        if npx is None:
            logger.info("npx not found; compiling directly with solc")
            return
        try:
            proc = subprocess.run(
                [npx, "--no-install", "hardhat", "compile"],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("npx hardhat compile could not run (%s); using solc", exc)
            return
        if proc.returncode != 0:
            logger.info(
                "npx hardhat compile unavailable/failed; compiling directly with solc"
            )
            logger.debug("hardhat output: %s", (proc.stderr or proc.stdout or "")[:1000])

    def _compile_group(
        self,
        root: Path,
        sources: dict[str, str],
        options: Any,
        include_paths: list[str],
        pinned: str | None,
    ) -> CompilationArtifacts:
        version = select_version(list(sources.values()), preferred=pinned)
        std_input = build_standard_json_input(
            sources,
            with_abi_bytecode=options.get("with_abi_bytecode", False),
            remappings=options.get("solc_remaps"),
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
            remappings=options.get("solc_remaps"),
            include_paths=include_paths,
        )
