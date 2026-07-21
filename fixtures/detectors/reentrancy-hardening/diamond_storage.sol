// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: ERC-7201 "diamond storage" — writes through a local
/// storage pointer (`$.field = ...`) are state mutations of the storage
/// region, and reads through the pointer are region reads.
contract DiamondVault {
    struct AppStorage {
        mapping(address => uint256) balances;
        uint256 total;
    }

    // keccak256("diamond.vault.app.storage") - 1 (illustrative constant)
    bytes32 private constant SLOT =
        0x9d8059a24cb596f1948a937c2c163cf14465c2a24abfd3cd009eec4ac4c39800;

    function _getAppStorage() private pure returns (AppStorage storage $) {
        assembly {
            $.slot := SLOT
        }
    }

    /// VULNERABLE (no-eth): the AppStorage region is written after the
    /// external call and read before it.
    function ping(uint256 amount) external {
        AppStorage storage $ = _getAppStorage();
        uint256 current = $.balances[msg.sender];
        (bool ok, ) = msg.sender.call("");
        require(ok, "call failed");
        $.balances[msg.sender] = amount;
    }
}

contract DiamondVaultChecked {
    struct AppStorage {
        mapping(address => uint256) balances;
    }

    bytes32 private constant SLOT =
        0x1d8059a24cb596f1948a937c2c163cf14465c2a24abfd3cd009eec4ac4c39800;

    function _getAppStorage() private pure returns (AppStorage storage $) {
        assembly {
            $.slot := SLOT
        }
    }

    /// SAFE: the region write happens before the external call (CEI).
    function ping(uint256 amount) external {
        AppStorage storage $ = _getAppStorage();
        $.balances[msg.sender] = amount;
        (bool ok, ) = msg.sender.call("");
        require(ok, "call failed");
    }
}
