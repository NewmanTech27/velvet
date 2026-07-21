"""solc standard-JSON document adapter. Original clean-room implementation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from velvet.compile.artifacts import (
    CompilationArtifacts,
    Filename,
    SourceUnitInfo,
)


class StandardJsonAdapter:
    """Consume a user-supplied solc standard-JSON *output* document."""

    def matches(self, target: str) -> bool:
        if not (target.endswith(".json") and Path(target).is_file()):
            return False
        try:
            doc = json.loads(Path(target).read_text(encoding="utf-8"))
        except Exception:
            return False
        return isinstance(doc, dict) and "sources" in doc and any(
            "ast" in v for v in doc.get("sources", {}).values() if isinstance(v, dict)
        )

    def compile(self, target: str, **options: Any) -> list[CompilationArtifacts]:
        path = Path(target).resolve()
        doc = json.loads(path.read_text(encoding="utf-8"))
        artifacts = CompilationArtifacts(
            compiler_version=doc.get("compiler", {}).get("version", ""),
            working_dir=str(path.parent),
        )
        for name, unit in doc.get("sources", {}).items():
            if "ast" not in unit:
                continue
            abs_path = str((path.parent / name).resolve())
            try:
                src_text = Path(abs_path).read_text(encoding="utf-8")
            except OSError:
                src_text = ""
            artifacts.source_units[unit.get("id", len(artifacts.source_units))] = (
                SourceUnitInfo(
                    source_id=unit.get("id", -1),
                    filename=Filename(absolute=abs_path, used=name),
                    ast=unit["ast"],
                    source=src_text,
                )
            )
        for _file, contracts in doc.get("contracts", {}).items():
            for cname, cdata in contracts.items():
                artifacts.abis[cname] = cdata.get("abi", [])
                artifacts.bytecode[cname] = {
                    "init": cdata.get("evm", {}).get("bytecode", {}).get("object", ""),
                    "deployed": cdata.get("evm", {})
                    .get("deployedBytecode", {})
                    .get("object", ""),
                }
        return [artifacts]
