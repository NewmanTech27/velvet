"""Direct solc standard-JSON invocation. Original clean-room implementation."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

import solcx

from velvet.exceptions import CompilationError


def _version_at_least(version: str, floor: tuple[int, int, int]) -> bool:
    """True when ``version`` (e.g. ``"0.8.24"``) is >= ``floor``."""
    try:
        parts = [int(p) for p in version.split(".")[:3]]
    except ValueError:
        return True  # unknown scheme: assume modern
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts) >= floor


@dataclass
class SolcOutput:
    """Parsed standard-JSON output plus the version that produced it."""

    raw: dict[str, Any]
    version: str

    @property
    def sources(self) -> dict[str, Any]:
        return self.raw.get("sources", {})

    @property
    def contracts(self) -> dict[str, Any]:
        return self.raw.get("contracts", {})

    def diagnostics(self, severity: str | None = None) -> list[dict[str, Any]]:
        diags = self.raw.get("errors", []) or []
        if severity is None:
            return diags
        return [d for d in diags if d.get("severity") == severity]


def build_standard_json_input(
    sources: dict[str, str],
    *,
    with_abi_bytecode: bool = False,
    remappings: list[str] | None = None,
) -> dict[str, Any]:
    """Build the standard-JSON input requesting the AST per source file."""
    output_selection: dict[str, Any] = {"*": {"": ["ast"]}}
    if with_abi_bytecode:
        output_selection["*"]["*"] = ["abi", "evm.bytecode", "evm.deployedBytecode"]
    settings: dict[str, Any] = {"outputSelection": output_selection}
    if remappings:
        settings["remappings"] = remappings
    return {
        "language": "Solidity",
        "sources": {name: {"content": content} for name, content in sources.items()},
        "settings": settings,
    }


def run_solc_standard_json(
    std_input: dict[str, Any],
    version: str,
    *,
    base_path: str | None = None,
    include_paths: list[str] | None = None,
    extra_args: list[str] | None = None,
    allow_paths: list[str] | None = None,
) -> SolcOutput:
    """Invoke the solc binary for `version` with a standard-JSON input.

    Raises CompilationError on hard compiler errors; warnings are propagated
    through the returned diagnostics.
    """
    try:
        solc_path = solcx.install.get_executable(version)
    except Exception:
        solcx.install_solc(version)
        solc_path = solcx.install.get_executable(version)

    cmd = [str(solc_path), "--standard-json"]
    # --base-path / --include-path / --allow-paths were introduced in
    # solc 0.8.8; older compilers reject them, so only pass them there.
    supports_path_flags = _version_at_least(version, (0, 8, 8))
    if base_path and supports_path_flags:
        cmd += ["--base-path", base_path]
    if include_paths and supports_path_flags:
        for p in include_paths:
            cmd += ["--include-path", p]
    if allow_paths and supports_path_flags:
        cmd += ["--allow-paths", ",".join(allow_paths)]
    if extra_args:
        cmd += list(extra_args)

    proc = subprocess.run(
        cmd,
        input=json.dumps(std_input),
        capture_output=True,
        text=True,
        timeout=300,
    )
    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise CompilationError(
            f"solc {version} produced no parseable output: {proc.stderr.strip() or exc}"
        ) from exc

    output = SolcOutput(raw=raw, version=version)
    errors = output.diagnostics("error")
    if errors:
        formatted = "\n".join(e.get("formattedMessage", e.get("message", "")) for e in errors)
        raise CompilationError(f"solc {version} compilation failed:\n{formatted}")
    return output
