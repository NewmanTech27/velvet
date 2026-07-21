"""Tests for the v0.2 compilation adapters (foundry/hardhat/brownie/explorer).

Explorer tests mock the HTTP layer — no live network calls are made.
Tests that invoke solc are marked ``integration`` like the existing suite.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from velvet.compile import compile_target
from velvet.compile.adapters.brownie import BrownieAdapter
from velvet.compile.adapters.explorer import (
    ExplorerAdapter,
    build_sourcecode_url,
    resolve_api_key,
    split_verified_source,
)
from velvet.compile.adapters.foundry import FoundryAdapter
from velvet.compile.adapters.hardhat import HardhatAdapter
from velvet.exceptions import AdapterError

FRAMEWORKS = Path(__file__).parent.parent / "fixtures" / "frameworks"
FOUNDRY_MINI = FRAMEWORKS / "foundry-mini"
HARDHAT_MINI = FRAMEWORKS / "hardhat-mini"
SMOKE = Path(__file__).parent.parent / "fixtures" / "smoke"

ADDRESS = "0xdAC17F958D2ee523a2206206994597C13D831ec7"

SINGLE_SOURCE = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity ^0.8.20;\n"
    "contract MiniToken {\n"
    "    mapping(address => uint256) public balanceOf;\n"
    "    function mint(uint256 amount) external {\n"
    "        balanceOf[msg.sender] += amount;\n"
    "    }\n"
    "}\n"
)

MULTI_TOKEN = (
    "// SPDX-License-Identifier: MIT\n"
    'pragma solidity ^0.8.20;\n'
    'import "./Lib.sol";\n'
    "contract Token { function add(uint256 a, uint256 b) external pure returns (uint256) { return Lib.add(a, b); } }\n"
)
MULTI_LIB = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity ^0.8.20;\n"
    "library Lib { function add(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; } }\n"
)


def _explorer_payload(source_code: str, name: str = "MiniToken", abi: str = "[]") -> dict:
    return {
        "status": "1",
        "message": "OK",
        "result": [
            {
                "SourceCode": source_code,
                "ABI": abi,
                "ContractName": name,
                "CompilerVersion": "v0.8.24+commit.e11b9ed9",
                "EVMVersion": "paris",
                "Library": "",
                "Runs": "200",
            }
        ],
    }


def _multipart_source() -> str:
    """Etherscan double-braced standard-JSON-input source payload."""
    doc = {
        "language": "Solidity",
        "sources": {
            "contracts/Token.sol": {"content": MULTI_TOKEN},
            "contracts/Lib.sol": {"content": MULTI_LIB},
        },
        "settings": {"optimizer": {"enabled": True, "runs": 200}},
    }
    return "{" + json.dumps(doc) + "}"


# ------------------------------------------------------------------ matches
def test_foundry_matches():
    adapter = FoundryAdapter()
    assert adapter.matches(str(FOUNDRY_MINI))
    assert not adapter.matches(str(SMOKE))  # plain dir without marker
    assert not adapter.matches(str(FOUNDRY_MINI / "src" / "Counter.sol"))


def test_hardhat_matches(tmp_path):
    adapter = HardhatAdapter()
    assert adapter.matches(str(HARDHAT_MINI))  # hardhat.config.js
    assert not adapter.matches(str(SMOKE))
    (tmp_path / "hardhat.config.ts").write_text("export default {};\n")
    assert adapter.matches(str(tmp_path))  # .ts variant


def test_brownie_matches(tmp_path):
    adapter = BrownieAdapter()
    assert not adapter.matches(str(SMOKE))
    (tmp_path / "brownie-config.yaml").write_text("compiler:\n  solc:\n    version: 0.8.24\n")
    assert adapter.matches(str(tmp_path))


def test_explorer_matches():
    adapter = ExplorerAdapter()
    assert adapter.matches(ADDRESS)
    assert adapter.matches(ADDRESS.lower())
    assert not adapter.matches("0x123")
    assert not adapter.matches("0x" + "g" * 40)
    assert not adapter.matches(str(SMOKE))
    assert not adapter.matches("contract.sol")


def test_autodetection_marker_priority(tmp_path, monkeypatch):
    """A dir with both foundry.toml and hardhat.config.js routes to foundry."""
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    (tmp_path / "hardhat.config.js").write_text("module.exports = {};\n")
    called: list[str] = []
    monkeypatch.setattr(
        FoundryAdapter, "compile", lambda self, t, **o: called.append("foundry") or []
    )
    monkeypatch.setattr(
        HardhatAdapter, "compile", lambda self, t, **o: called.append("hardhat") or []
    )
    compile_target(str(tmp_path))
    assert called == ["foundry"]


# ------------------------------------------------------------ foundry compile
@pytest.mark.integration
def test_foundry_compile_without_forge(monkeypatch):
    """Without a forge binary the adapter falls back to direct solc."""
    monkeypatch.setattr(
        "velvet.compile.adapters.foundry.shutil.which", lambda _name: None
    )
    artifacts = compile_target(str(FOUNDRY_MINI))
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.compiler_version == "0.8.24"  # pinned in foundry.toml
    assert "minilib/=lib/minilib/src/" in art.remappings
    used = {u.filename.used for u in art.source_units.values()}
    assert "src/Counter.sol" in used
    assert "lib/minilib/src/MathLib.sol" in used
    by_used = {u.filename.used: u for u in art.source_units.values()}
    assert by_used["lib/minilib/src/MathLib.sol"].is_dependency
    assert not by_used["src/Counter.sol"].is_dependency
    assert all(u.ast.get("nodeType") == "SourceUnit" for u in art.source_units.values())


@pytest.mark.integration
def test_foundry_ignore_compile_merges_out_artifacts(tmp_path):
    """--ignore-compile reuses existing out/ ABI+bytecode artifacts."""
    shutil.copytree(FOUNDRY_MINI, tmp_path, dirs_exist_ok=True)
    out_dir = tmp_path / "out" / "Counter.sol"
    out_dir.mkdir(parents=True)
    (out_dir / "Counter.json").write_text(
        json.dumps(
            {
                "abi": [{"type": "function", "name": "increment"}],
                "bytecode": {"object": "0xdead"},
                "deployedBytecode": {"object": "0xbeef"},
            }
        )
    )
    artifacts = compile_target(str(tmp_path), ignore_compile=True)
    art = artifacts[0]
    assert art.abis["Counter"] == [{"type": "function", "name": "increment"}]
    assert art.bytecode["Counter"] == {"init": "0xdead", "deployed": "0xbeef"}


# ------------------------------------------------------------ hardhat compile
@pytest.mark.integration
def test_hardhat_compile_resolves_node_modules(monkeypatch):
    """node_modules imports resolve via include-path and flag dependencies."""
    monkeypatch.setattr(
        "velvet.compile.adapters.hardhat.shutil.which", lambda _name: None
    )
    artifacts = compile_target(str(HARDHAT_MINI))
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.compiler_version == "0.8.24"  # scraped from hardhat.config.js
    by_used = {u.filename.used: u for u in art.source_units.values()}
    assert "contracts/MiniToken.sol" in by_used
    dep = by_used["@minipkg/contracts/Owned.sol"]
    assert dep.is_dependency
    assert "node_modules" in dep.filename.absolute
    assert dep.source.startswith("// SPDX-License-Identifier: MIT")


# ------------------------------------------------------------- brownie compile
@pytest.mark.integration
def test_brownie_compile(tmp_path):
    (tmp_path / "brownie-config.yaml").write_text(
        "compiler:\n  solc:\n    version: 0.8.24\n"
    )
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    (contracts / "Vault.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract Vault {\n"
        "    uint256 public total;\n"
        "    function deposit() external payable { total += msg.value; }\n"
        "}\n"
    )
    artifacts = compile_target(str(tmp_path))
    art = artifacts[0]
    assert art.compiler_version == "0.8.24"
    assert {u.filename.short for u in art.source_units.values()} == {"Vault.sol"}


# -------------------------------------------------------- explorer: pure unit
def test_split_verified_source_single():
    sources, remaps = split_verified_source(SINGLE_SOURCE, "MiniToken")
    assert sources == {"MiniToken.sol": SINGLE_SOURCE}
    assert remaps == []


def test_split_verified_source_multipart_double_braced():
    sources, _remaps = split_verified_source(_multipart_source(), "Token")
    assert set(sources) == {"contracts/Token.sol", "contracts/Lib.sol"}


def test_split_verified_source_multipart_single_braced():
    doc = {"language": "Solidity", "sources": {"a.sol": {"content": MULTI_LIB}}}
    sources, _ = split_verified_source(json.dumps(doc), "A")
    assert sources == {"a.sol": MULTI_LIB}


def test_explorer_api_key_resolution(monkeypatch):
    monkeypatch.delenv("VELVET_EXPLORER_API_KEY", raising=False)
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    monkeypatch.delenv("POLYGONSCAN_API_KEY", raising=False)
    assert resolve_api_key("mainnet", "EXPLICIT") == "EXPLICIT"
    assert resolve_api_key("mainnet") == ""
    monkeypatch.setenv("ETHERSCAN_API_KEY", "ENVKEY")
    assert resolve_api_key("mainnet") == "ENVKEY"
    monkeypatch.setenv("VELVET_EXPLORER_API_KEY", "GENERIC")
    assert resolve_api_key("mainnet") == "GENERIC"
    monkeypatch.setenv("POLYGONSCAN_API_KEY", "POLYKEY")
    assert resolve_api_key("polygon", None) == "GENERIC"
    monkeypatch.delenv("VELVET_EXPLORER_API_KEY")
    assert resolve_api_key("polygon", None) == "POLYKEY"


def test_explorer_url_contains_key_and_action():
    url = build_sourcecode_url("api.etherscan.io", ADDRESS, "KEY123")
    assert url.startswith("https://api.etherscan.io/api?")
    assert "action=getsourcecode" in url
    assert f"address={ADDRESS}" in url
    assert "apikey=KEY123" in url


# ----------------------------------------------------- explorer: mocked fetch
def _mock_fetch(monkeypatch, payload):
    seen: list[str] = []

    def fake(url: str, timeout: int = 0):
        seen.append(url)
        return payload

    monkeypatch.setattr("velvet.compile.adapters.explorer._http_get_json", fake)
    return seen


@pytest.mark.integration
def test_explorer_compile_single_file(monkeypatch):
    seen = _mock_fetch(
        monkeypatch,
        _explorer_payload(SINGLE_SOURCE, abi='[{"type":"function","name":"mint"}]'),
    )
    artifacts = compile_target(
        ADDRESS, explorer_network="mainnet", explorer_api_key="K"
    )
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.compiler_version == "0.8.24"  # v0.8.24+commit... stripped
    assert art.abis["MiniToken"] == [{"type": "function", "name": "mint"}]
    used = {u.filename.used for u in art.source_units.values()}
    assert used == {"MiniToken.sol"}
    assert "api.etherscan.io" in seen[0] and "apikey=K" in seen[0]


@pytest.mark.integration
def test_explorer_compile_multipart(monkeypatch):
    _mock_fetch(monkeypatch, _explorer_payload(_multipart_source(), name="Token"))
    artifacts = compile_target(ADDRESS, explorer_network="sepolia")
    art = artifacts[0]
    used = {u.filename.used for u in art.source_units.values()}
    assert used == {"contracts/Token.sol", "contracts/Lib.sol"}
    assert all(u.source for u in art.source_units.values())


def test_explorer_unverified_contract(monkeypatch):
    _mock_fetch(monkeypatch, _explorer_payload("", name=""))
    with pytest.raises(AdapterError, match="not source-verified"):
        compile_target(ADDRESS)


def test_explorer_api_error(monkeypatch):
    _mock_fetch(
        monkeypatch,
        {"status": "0", "message": "NOTOK", "result": "Invalid address"},
    )
    with pytest.raises(AdapterError, match="NOTOK"):
        compile_target(ADDRESS)


def test_explorer_unknown_network():
    with pytest.raises(AdapterError, match="Unknown explorer network"):
        compile_target(ADDRESS, explorer_network="venus")


# ------------------------------------------------------------ force_framework
def test_force_framework_unknown():
    with pytest.raises(AdapterError, match="Unknown framework"):
        compile_target(str(SMOKE), force_framework="truffle")


@pytest.mark.integration
def test_force_framework_overrides_detection(tmp_path):
    """force_framework routes a markerless dir through the named adapter."""
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    (contracts / "Foo.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract Foo { function f() external pure returns (uint256) { return 1; } }\n"
    )
    # No hardhat.config.js present: auto-detection would treat it as a plain
    # project dir; forcing hardhat must route through HardhatAdapter.
    assert not HardhatAdapter().matches(str(tmp_path))
    artifacts = compile_target(str(tmp_path), force_framework="hardhat", solc="0.8.24")
    art = artifacts[0]
    assert art.compiler_version == "0.8.24"
    assert {u.filename.short for u in art.source_units.values()} == {"Foo.sol"}


# ------------------------------------------------------- session-level wiring
@pytest.mark.integration
def test_session_explorer_options(monkeypatch):
    """Velvet("0x…", explorer_network=..., explorer_api_key=...) works."""
    from velvet.session import Velvet

    seen = _mock_fetch(monkeypatch, _explorer_payload(SINGLE_SOURCE))
    session = Velvet(ADDRESS, explorer_network="mainnet", explorer_api_key="SESSKEY")
    assert "apikey=SESSKEY" in seen[0]
    names = {c.name for c in session.contracts}
    assert "MiniToken" in names


@pytest.mark.integration
def test_session_force_framework(monkeypatch):
    """Velvet(".", force_framework="foundry") routes through FoundryAdapter."""
    from velvet.session import Velvet

    monkeypatch.setattr(
        "velvet.compile.adapters.foundry.shutil.which", lambda _name: None
    )
    session = Velvet(str(FOUNDRY_MINI), force_framework="foundry")
    names = {c.name for c in session.contracts}
    assert "Counter" in names
    assert "MathLib" in names  # lib dependency compiled as well


# ------------------------------------------------------- remappings.txt unit
def test_foundry_remappings_txt_parsing(tmp_path):
    from velvet.compile.adapters.foundry import gather_remappings, parse_remappings_txt

    (tmp_path / "remappings.txt").write_text(
        "# comment line\n"
        "forge-std/=lib/forge-std/src/\n"
        "\n"
        "@openzeppelin/=lib/oz/ # trailing comment\n"
        "not-a-remapping-line\n"
    )
    assert parse_remappings_txt(tmp_path) == [
        "forge-std/=lib/forge-std/src/",
        "@openzeppelin/=lib/oz/",
    ]
    merged = gather_remappings(tmp_path, {"remappings": ["forge-std/=lib/forge-std/src/", "a/=b/"]})
    assert merged == [
        "forge-std/=lib/forge-std/src/",
        "@openzeppelin/=lib/oz/",
        "a/=b/",
    ]


@pytest.mark.integration
def test_foundry_compile_with_failing_forge(tmp_path, monkeypatch):
    """A forge binary that fails still leaves our solc compilation working."""
    fake_forge = tmp_path / "forge"
    fake_forge.write_text("#!/bin/sh\nexit 1\n")
    fake_forge.chmod(0o755)
    monkeypatch.setattr(
        "velvet.compile.adapters.foundry.shutil.which", lambda _name: str(fake_forge)
    )
    artifacts = compile_target(str(FOUNDRY_MINI))
    assert {u.filename.short for u in artifacts[0].source_units.values()} >= {
        "Counter.sol",
        "MathLib.sol",
    }


@pytest.mark.integration
def test_session_autodetects_foundry(monkeypatch):
    """Velvet(foundry_dir) without force_framework uses FoundryAdapter."""
    from velvet.session import Velvet

    monkeypatch.setattr(
        "velvet.compile.adapters.foundry.shutil.which", lambda _name: None
    )
    session = Velvet(str(FOUNDRY_MINI))
    names = {c.name for c in session.contracts}
    assert {"Counter", "MathLib"} <= names
