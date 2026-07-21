// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: every writer honors the documented protection.
contract GuardedTreasuryConfig {
    address public admin;

    /// @custom:security write-protection="onlyAdmin()"
    address public treasury;

    /// @custom:security write-protection="ensureAdmin()"
    uint256 public feeBps;

    uint256 public version;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    function ensureAdmin() internal view {
        require(msg.sender == admin, "not admin");
    }

    /// SAFE: modifier applies the documented protection.
    function setTreasury(address newTreasury) external onlyAdmin {
        require(newTreasury != address(0), "zero treasury");
        treasury = newTreasury;
    }

    /// SAFE: the named check function is invoked before writing.
    function setFeeBps(uint256 newFeeBps) external {
        ensureAdmin();
        feeBps = newFeeBps;
    }

    /// Unannotated variable: free to write.
    function bumpVersion(uint256 newVersion) external {
        version = newVersion;
    }
}
