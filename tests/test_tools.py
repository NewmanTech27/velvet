"""Tests for the v1 companion tools (spec/printers-and-tools.md §B):

- ``velvet-check-erc`` — ERC-20/721/1155 conformance checker;
- ``velvet-flat`` — source flattener;
- ``velvet-interface`` — interface generator.

Original clean-room implementation.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from velvet.compile import compile_target
from velvet.session import Velvet
from velvet.tools import check_erc, flat, interface
from velvet.tools.common import merged_solidity_pragma

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "tools"
ERC20 = FIXTURES / "erc20"
ERC721 = FIXTURES / "erc721"
ERC1155 = FIXTURES / "erc1155"
MULTIFILE = FIXTURES / "multifile"
INTERFACE = FIXTURES / "interface"


def _compile_contracts(path: Path) -> list[str]:
    """Compile a .sol file with velvet.compile and return contract names."""
    artifacts = compile_target(str(path), with_abi_bytecode=True)
    return sorted(name for a in artifacts for name in a.abis)


# ---------------------------------------------------------------------------
# velvet-check-erc
# ---------------------------------------------------------------------------


class TestCheckERC20:
    def test_conformant_token_passes(self, capsys):
        code = check_erc.main([str(ERC20 / "GoodToken.sol"), "GoodToken"])
        out = capsys.readouterr().out
        assert code == 0
        assert "# Check ERC20" in out
        assert "[✓] transfer(address,uint256) is present" in out
        assert "[✓] transfer(address,uint256) returns bool" in out
        assert "[✓] Transfer(address,address,uint256) is emitted" in out
        # optional functions satisfied via public-variable getters
        assert "[✓] name() is present" in out
        assert "[✓] decimals() returns uint8" in out
        assert "RESULT: PASS" in out

    def test_conformant_token_report(self):
        session = Velvet(str(ERC20 / "GoodToken.sol"))
        contract = session.get_contract_from_name("GoodToken")
        report = check_erc.check_contract(contract, check_erc.STANDARDS["erc20"])
        assert report.ok
        assert report.failures == 0
        assert report.warnings == 0

    def test_deviant_token_fails_specific_checks(self, capsys):
        code = check_erc.main([str(ERC20 / "BadToken.sol"), "BadToken"])
        out = capsys.readouterr().out
        assert code == 1
        # 1. transfer must return bool
        assert "[ ] transfer(address,uint256) -> () should return bool" in out
        # 2. balanceOf must be view
        assert "[ ] balanceOf(address) should be view (is nonpayable)" in out
        # 3. allowance missing
        assert "[ ] allowance(address,address) is missing" in out
        # 4. approve must emit Approval
        assert "[ ] Approval(address,address,uint256) is not emitted" in out
        # 5. Transfer parameter 1 must be indexed
        assert "[ ] parameter 1 should be indexed" in out
        # 6. optional functions are warnings, not failures
        assert "[ ] name() is missing (optional)" in out
        assert "RESULT: FAIL" in out

    def test_deviant_token_report_accounting(self):
        session = Velvet(str(ERC20 / "BadToken.sol"))
        contract = session.get_contract_from_name("BadToken")
        report = check_erc.check_contract(contract, check_erc.STANDARDS["erc20"])
        assert not report.ok
        assert report.failures == 5
        assert report.warnings == 3  # name/symbol/decimals
        # passing checks are not penalized (getters, transitive emission)
        assert any(
            "[✓] Transfer(address,address,uint256) is emitted" in line
            for line in report.lines
        )

    def test_default_erc_is_20(self, capsys):
        code = check_erc.main([str(ERC20 / "GoodToken.sol"), "GoodToken", "--erc", "20"])
        assert code == 0
        assert "# Check ERC20" in capsys.readouterr().out


class TestCheckERC721:
    def test_conformant_nft_passes(self, capsys):
        code = check_erc.main([str(ERC721 / "MiniNFT.sol"), "MiniNFT", "--erc", "721"])
        out = capsys.readouterr().out
        assert code == 0
        assert "# Check ERC721" in out
        assert "[✓] supportsInterface(bytes4) [ERC-165] is present" in out
        assert "[✓] safeTransferFrom(address,address,uint256,bytes) is present" in out
        assert "RESULT: PASS" in out

    def test_non_nft_fails(self, capsys):
        code = check_erc.main([str(ERC20 / "GoodToken.sol"), "GoodToken", "--erc", "721"])
        out = capsys.readouterr().out
        assert code == 1
        assert "[ ] supportsInterface(bytes4) [ERC-165] is missing" in out
        assert "[ ] ownerOf(uint256) is missing" in out

    def test_erc721_event_indexing(self):
        session = Velvet(str(ERC721 / "MiniNFT.sol"))
        contract = session.get_contract_from_name("MiniNFT")
        report = check_erc.check_contract(contract, check_erc.STANDARDS["erc721"])
        assert report.ok  # required checks pass; metadata/enumerable optional


class TestCheckERC1155:
    def test_conformant_multitoken_passes(self, capsys):
        code = check_erc.main(
            [str(ERC1155 / "MiniMultiToken.sol"), "MiniMultiToken", "--erc", "1155"]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "# Check ERC1155" in out
        assert "[✓] TransferSingle(address,address,address,uint256,uint256) is emitted" in out
        assert "[✓] uri(uint256) is present" in out
        assert "RESULT: PASS" in out

    def test_batch_signatures_checked(self):
        session = Velvet(str(ERC1155 / "MiniMultiToken.sol"))
        contract = session.get_contract_from_name("MiniMultiToken")
        report = check_erc.check_contract(contract, check_erc.STANDARDS["erc1155"])
        assert report.ok
        assert any(
            "[✓] balanceOfBatch(address[],uint256[]) returns uint256[]" in line
            for line in report.lines
        )


class TestCheckERCUnits:
    @pytest.mark.parametrize(
        "raw,key",
        [("20", "erc20"), ("erc20", "erc20"), ("ERC-721", "erc721"), ("1155", "erc1155")],
    )
    def test_normalize_standard_key(self, raw, key):
        assert check_erc.normalize_standard_key(raw) == key

    def test_normalize_standard_key_rejects_unknown(self):
        from velvet.exceptions import VelvetError

        with pytest.raises(VelvetError):
            check_erc.normalize_standard_key("erc777")

    @pytest.mark.parametrize(
        "required,actual,ok",
        [
            ("view", "view", True),
            ("view", "pure", True),  # pure is stronger, keeps the guarantee
            ("view", "nonpayable", False),
            ("payable", "payable", True),
            ("payable", "nonpayable", True),  # EIP-721 allows stronger non-payable
            ("payable", "view", False),
            ("nonpayable", "nonpayable", True),
            ("nonpayable", "payable", True),
            ("nonpayable", "view", False),
            ("nonpayable", "pure", False),
        ],
    )
    def test_mutability_ok(self, required, actual, ok):
        assert check_erc.mutability_ok(required, actual) is ok

    def test_unknown_contract_exit_2(self, capsys):
        code = check_erc.main([str(ERC20 / "GoodToken.sol"), "Nope"])
        assert code == 2
        assert "not found" in capsys.readouterr().err

    def test_unsupported_standard_exit_2(self, capsys):
        code = check_erc.main([str(ERC20 / "GoodToken.sol"), "GoodToken", "--erc", "777"])
        assert code == 2
        assert "unsupported" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# velvet-flat
# ---------------------------------------------------------------------------


class TestFlat:
    def test_onefile_structure(self, capsys):
        code = flat.main([str(MULTIFILE)])
        out = capsys.readouterr().out
        assert code == 0
        assert out.count("pragma solidity") == 1  # merged, not duplicated
        assert out.count("SPDX-License-Identifier") == 1
        assert not any(
            line.startswith("import") for line in out.splitlines()
        ), "no import statements may remain"
        # every source unit appears exactly once (deduped despite the
        # duplicate import of base/Owned.sol)
        assert out.count("contract Owned") == 1
        assert out.count("library Counters") == 1
        for name in ("Owned", "Counters", "VaultBase", "TokenVault", "Standalone"):
            assert name in out

    def test_onefile_dependency_order(self, capsys):
        flat.main([str(MULTIFILE)])
        out = capsys.readouterr().out
        # dependencies must be emitted before their importers
        assert out.index("base/Owned.sol") < out.index("tokens/VaultBase.sol")
        assert out.index("tokens/VaultBase.sol") < out.index("tokens/TokenVault.sol")

    def test_onefile_output_compiles(self, tmp_path, capsys):
        assert flat.main([str(MULTIFILE)]) == 0
        out = capsys.readouterr().out
        target = tmp_path / "flattened.sol"
        target.write_text(out)
        assert _compile_contracts(target) == [
            "Counters",
            "Owned",
            "Standalone",
            "TokenVault",
            "VaultBase",
        ]

    def test_output_option_writes_file(self, tmp_path):
        target = tmp_path / "out.sol"
        assert flat.main([str(MULTIFILE), "-o", str(target)]) == 0
        assert target.is_file()
        assert "contract TokenVault" in target.read_text()

    def test_contract_restriction(self, tmp_path, capsys):
        target = tmp_path / "token_vault.sol"
        code = flat.main(
            [str(MULTIFILE), "--contract", "TokenVault", "-o", str(target)]
        )
        assert code == 0
        out = target.read_text()
        assert "contract TokenVault" in out
        assert "contract VaultBase" in out
        assert "contract Owned" in out
        assert "library Counters" in out
        assert "Standalone" not in out  # unrelated unit excluded
        assert _compile_contracts(target) == [
            "Counters",
            "Owned",
            "TokenVault",
            "VaultBase",
        ]

    def test_most_derived_strategy(self, tmp_path):
        out_dir = tmp_path / "flat-md"
        code = flat.main(
            [str(MULTIFILE), "--strategy", "most-derived", "--dir", str(out_dir)]
        )
        assert code == 0
        names = sorted(p.name for p in out_dir.glob("*.sol"))
        # Owned and VaultBase are inherited -> not most-derived
        assert names == ["Counters.sol", "Standalone.sol", "TokenVault.sol"]
        assert _compile_contracts(out_dir / "TokenVault.sol") == [
            "Counters",
            "Owned",
            "TokenVault",
            "VaultBase",
        ]

    def test_bad_target_exit_2(self, capsys):
        code = flat.main([str(FIXTURES / "does-not-exist")])
        assert code == 2

    def test_unknown_contract_exit_2(self, capsys):
        code = flat.main([str(MULTIFILE), "--contract", "Nope"])
        assert code == 2
        assert "not found" in capsys.readouterr().err

    def test_merged_solidity_pragma(self):
        merged = merged_solidity_pragma(
            ["pragma solidity ^0.8.0;", "pragma solidity >=0.8.0 <0.9.0;",
             "pragma solidity ^0.8.0;"]
        )
        assert merged == "^0.8.0 >=0.8.0 <0.9.0"


# ---------------------------------------------------------------------------
# velvet-interface
# ---------------------------------------------------------------------------


class TestInterface:
    def test_generates_expected_surface(self, capsys):
        code = interface.main([str(INTERFACE / "Auction.sol"), "Auction"])
        out = capsys.readouterr().out
        assert code == 0
        assert "interface IAuction {" in out
        # public/external functions with mutability and returns
        assert "function bid(uint256 amount) external;" in out
        assert "function placeBid(Bid calldata newBid) external;" in out
        assert "function currentState() external view returns (AuctionState);" in out
        assert "function refund(address who, uint256 amount) external returns (bool);" in out
        # public state-variable getters are part of the external surface
        assert "function beneficiary() external view returns (address);" in out
        assert "function pendingReturns(address) external view returns (uint256);" in out
        # internal functions and the constructor are excluded
        assert "_tally" not in out
        assert "constructor" not in out

    def test_supporting_declarations(self, capsys):
        interface.main([str(INTERFACE / "Auction.sol"), "Auction"])
        out = capsys.readouterr().out
        assert "event BidPlaced(address indexed bidder, uint256 amount);" in out
        assert "event Closed(uint256 finalAmount);" in out
        assert "error Unauthorized(address caller);" in out
        assert "error InsufficientBalance(uint256 available, uint256 required);" in out
        assert "enum AuctionState { Open, Closed, Settled }" in out
        assert "struct Bid {" in out

    def test_output_compiles(self, tmp_path):
        target = tmp_path / "IAuction.sol"
        code = interface.main(
            [str(INTERFACE / "Auction.sol"), "Auction", "-o", str(target)]
        )
        assert code == 0
        assert _compile_contracts(target) == ["IAuction"]

    def test_exclude_flags(self, capsys):
        code = interface.main(
            [
                str(INTERFACE / "Auction.sol"),
                "Auction",
                "--exclude-events",
                "--exclude-errors",
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "event BidPlaced" not in out
        assert "error Unauthorized" not in out
        assert "enum AuctionState" in out  # not excluded

    def test_unroll_structs(self, capsys):
        code = interface.main(
            [str(INTERFACE / "Auction.sol"), "Auction", "--unroll-structs"]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "function placeBid(address, uint256) external;" in out
        assert "struct Bid {" not in out  # no longer needed

    def test_unknown_contract_exit_2(self, capsys):
        code = interface.main([str(INTERFACE / "Auction.sol"), "Nope"])
        assert code == 2
        assert "not found" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# console-script smoke tests (installed entry points)
# ---------------------------------------------------------------------------


class TestConsoleScripts:
    def test_velvet_check_erc(self):
        result = subprocess.run(
            [sys.executable, "-m", "velvet.tools.check_erc",
             str(ERC20 / "GoodToken.sol"), "GoodToken"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "RESULT: PASS" in result.stdout

    def test_velvet_flat(self, tmp_path):
        result = subprocess.run(
            [sys.executable, "-m", "velvet.tools.flat", str(MULTIFILE)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "contract TokenVault" in result.stdout

    def test_velvet_interface(self):
        result = subprocess.run(
            [sys.executable, "-m", "velvet.tools.interface",
             str(INTERFACE / "Auction.sol"), "Auction"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "interface IAuction" in result.stdout
