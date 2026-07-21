"""Single .sol file adapter. Original clean-room implementation."""

from __future__ import annotations

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


class SolFileAdapter:
    """Compile one .sol file (imports resolved through solc base-path)."""

    def matches(self, target: str) -> bool:
        return target.endswith(".sol") and Path(target).is_file()

    def compile(self, target: str, **options: Any) -> list[CompilationArtifacts]:
        path = Path(target).resolve()
        source = path.read_text(encoding="utf-8")
        version = select_version(
            [source], preferred=options.get("solc")
        )
        std_input = build_standard_json_input(
            {path.name: source},
            with_abi_bytecode=options.get("with_abi_bytecode", False),
            remappings=options.get("solc_remaps"),
        )
        output = run_solc_standard_json(
            std_input,
            version,
            base_path=str(path.parent),
            include_paths=options.get("include_paths"),
            extra_args=options.get("solc_args"),
        )
        artifacts = CompilationArtifacts(
            compiler_version=version, working_dir=str(path.parent)
        )
        for name, unit in output.sources.items():
            abs_path = str((path.parent / name).resolve())
            filename = Filename(absolute=abs_path, used=name)
            src_text = (
                source
                if name == path.name
                else Path(abs_path).read_text(encoding="utf-8")
            )
            artifacts.source_units[unit["id"]] = SourceUnitInfo(
                source_id=unit["id"], filename=filename, ast=unit["ast"], source=src_text
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
        return [artifacts]
