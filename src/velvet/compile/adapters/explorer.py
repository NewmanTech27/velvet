"""Block-explorer contract-address adapter. Original clean-room implementation.

Detection: a ``0x``-prefixed 40-hex-character contract address.

Strategy: fetch the verified source from an Etherscan-family API
(``module=contract&action=getsourcecode``) and compile it with our own solc
standard-JSON invocation. Both single-file verified sources and multi-part
standard-JSON-input sources (the ``{{ ... }}`` double-braced form the
explorers return) are handled. Sources are virtual (never written to disk);
the AST always comes from our own solc run, while the ABI published by the
explorer is attached for the verified contract.

Options: ``explorer_network`` (default ``mainnet``), ``explorer_api_key``
(falling back to ``$VELVET_EXPLORER_API_KEY``, then the per-network variable
such as ``$ETHERSCAN_API_KEY``/``$POLYGONSCAN_API_KEY``), ``solc`` to override
the compiler version reported by the explorer.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.parse
import urllib.request
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
from velvet.exceptions import AdapterError

logger = logging.getLogger("velvet.compile.explorer")

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_VERSION_RE = re.compile(r"v?(\d+\.\d+\.\d+)")

#: Etherscan-family API hosts per network name.
NETWORKS: dict[str, str] = {
    "mainnet": "api.etherscan.io",
    "sepolia": "api-sepolia.etherscan.io",
    "polygon": "api.polygonscan.com",
    "arbitrum": "api.arbiscan.io",
    "optimism": "api-optimistic.etherscan.io",
    "base": "api.basescan.org",
    "bsc": "api.bscscan.com",
}

#: Per-network environment variables probed for an API key.
NETWORK_ENV_KEYS: dict[str, str] = {
    "mainnet": "ETHERSCAN_API_KEY",
    "sepolia": "ETHERSCAN_API_KEY",
    "polygon": "POLYGONSCAN_API_KEY",
    "arbitrum": "ARBISCAN_API_KEY",
    "optimism": "OPTIMISTIC_ETHERSCAN_API_KEY",
    "base": "BASESCAN_API_KEY",
    "bsc": "BSCSCAN_API_KEY",
}

GENERIC_ENV_KEY = "VELVET_EXPLORER_API_KEY"
_USER_AGENT = "velvet-analyzer/0.2 (+https://github.com/velvet-analyzer)"
_TIMEOUT_SECONDS = 30


def _http_get_json(url: str, timeout: int = _TIMEOUT_SECONDS) -> dict[str, Any]:
    """GET ``url`` and parse the JSON body (mocked in tests; no live calls)."""
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def resolve_api_key(network: str, explicit: str | None = None) -> str:
    """API key resolution order: option > generic env > per-network env."""
    if explicit:
        return explicit
    for env_key in (GENERIC_ENV_KEY, NETWORK_ENV_KEYS.get(network, ""), "ETHERSCAN_API_KEY"):
        if env_key and os.environ.get(env_key):
            return os.environ[env_key]
    return ""


def build_sourcecode_url(host: str, address: str, api_key: str) -> str:
    """Build the getsourcecode endpoint URL."""
    query = urllib.parse.urlencode(
        {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": api_key,
        }
    )
    return f"https://{host}/api?{query}"


def split_verified_source(
    source_code: str, contract_name: str
) -> tuple[dict[str, str], list[str]]:
    """Split an explorer ``SourceCode`` payload into {path: content}.

    Handles plain single-file sources and JSON standard-input payloads —
    including the double-braced ``{{ ... }}`` wrapping explorers use to
    distinguish them. Returns (sources, remappings-from-settings).
    """
    text = source_code.strip()
    if text.startswith("{"):
        doc: Any = None
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            if text.startswith("{{"):
                try:
                    doc = json.loads(text[1:-1])
                except json.JSONDecodeError:
                    doc = None
        if isinstance(doc, dict) and isinstance(doc.get("sources"), dict):
            sources: dict[str, str] = {}
            for name, entry in doc["sources"].items():
                if isinstance(entry, dict) and "content" in entry:
                    sources[name] = entry["content"]
                elif isinstance(entry, str):
                    sources[name] = entry
            if sources:
                settings = doc.get("settings") or {}
                remappings = settings.get("remappings") or []
                return sources, [str(r) for r in remappings]
    return {f"{contract_name or 'Contract'}.sol": source_code}, []


class ExplorerAdapter:
    """Fetch and compile verified sources for a 0x contract address."""

    name = "explorer"

    def matches(self, target: str) -> bool:
        return bool(_ADDRESS_RE.match(target.strip()))

    def compile(self, target: str, **options: Any) -> list[CompilationArtifacts]:
        address = target.strip()
        network = str(options.get("explorer_network") or "mainnet").lower()
        host = NETWORKS.get(network)
        if host is None:
            raise AdapterError(
                f"Unknown explorer network {network!r}; "
                f"expected one of {sorted(NETWORKS)}"
            )
        api_key = resolve_api_key(network, options.get("explorer_api_key"))
        url = build_sourcecode_url(host, address, api_key)
        logger.info("Fetching verified source for %s on %s", address, network)
        payload = _http_get_json(url)

        if str(payload.get("status")) != "1":
            raise AdapterError(
                f"Explorer lookup failed for {address} on {network}: "
                f"{payload.get('message', '')} {payload.get('result', '')}".strip()
            )
        result = payload.get("result")
        if not isinstance(result, list) or not result:
            raise AdapterError(f"Explorer returned no result for {address} on {network}")
        entry = result[0]
        source_code = entry.get("SourceCode") or ""
        if not source_code.strip():
            raise AdapterError(
                f"Contract {address} on {network} is not source-verified on the explorer"
            )

        contract_name = entry.get("ContractName") or "Contract"
        sources, remappings = split_verified_source(source_code, contract_name)

        version = options.get("solc") or self._compiler_version(
            entry.get("CompilerVersion", ""), sources
        )
        std_input = build_standard_json_input(
            sources,
            with_abi_bytecode=options.get("with_abi_bytecode", False),
            remappings=remappings or None,
        )
        output = run_solc_standard_json(
            std_input, version, extra_args=options.get("solc_args")
        )

        artifacts = CompilationArtifacts(
            compiler_version=version,
            working_dir=f"explorer:{network}:{address}",
        )
        artifacts.remappings = remappings
        for name, unit in output.sources.items():
            artifacts.source_units[unit["id"]] = SourceUnitInfo(
                source_id=unit["id"],
                filename=Filename(absolute=name, used=name),
                ast=unit["ast"],
                source=sources.get(name, ""),
            )
        for _file, contracts in output.contracts.items():
            for cname, cdata in contracts.items():
                artifacts.bytecode[cname] = {
                    "init": cdata.get("evm", {}).get("bytecode", {}).get("object", ""),
                    "deployed": cdata.get("evm", {})
                    .get("deployedBytecode", {})
                    .get("object", ""),
                }
        explorer_abi = self._parse_abi(entry.get("ABI"))
        if explorer_abi is not None:
            artifacts.abis[contract_name] = explorer_abi
        elif output.contracts:
            for _file, contracts in output.contracts.items():
                for cname, cdata in contracts.items():
                    artifacts.abis[cname] = cdata.get("abi", [])
        return [artifacts]

    # ------------------------------------------------------------ internals
    @staticmethod
    def _compiler_version(raw: str, sources: dict[str, str]) -> str:
        """``v0.8.24+commit.e11b9ed9`` -> ``0.8.24``; pragma fallback."""
        match = _VERSION_RE.search(raw or "")
        if match:
            return match.group(1)
        return select_version(list(sources.values()))

    @staticmethod
    def _parse_abi(raw: Any) -> list | None:
        if isinstance(raw, list):
            return raw
        if isinstance(raw, str) and raw.strip().startswith("["):
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                return None
            return parsed if isinstance(parsed, list) else None
        return None
