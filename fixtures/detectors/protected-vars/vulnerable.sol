// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: documented write-protection violated by one writer.
contract TreasuryConfig {
    address public admin;

    /// @custom:security write-protection="onlyAdmin()"
    address public treasury;

    /// @custom:security write-protection="onlyAdmin()"
    uint256 public feeBps;

    uint256 public version;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    /// Protected writer: OK.
    function setTreasury(address newTreasury) external onlyAdmin {
        require(newTreasury != address(0), "zero treasury");
        treasury = newTreasury;
    }

    /// VULNERABLE: writes treasury without the documented onlyAdmin guard.
    function migrateTreasury(address newTreasury) external {
        require(newTreasury != address(0), "zero treasury");
        treasury = newTreasury;
    }

    /// VULNERABLE: writes feeBps without the documented onlyAdmin guard.
    function setFeeBps(uint256 newFeeBps) external {
        feeBps = newFeeBps;
    }

    /// Unannotated variable: free to write.
    function bumpVersion(uint256 newVersion) external {
        version = newVersion;
    }
}
