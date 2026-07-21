// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: every address parameter validated before storage.
contract CheckedTeamWallet {
    address public admin;
    address payable public treasury;
    uint256 public threshold;

    /// SAFE: constructor parameter validated before storage.
    constructor(address foundation) {
        admin = msg.sender;
        require(foundation != address(0), "zero foundation");
        treasury = payable(foundation);
    }

    /// SAFE: explicit zero-address validation.
    function setAdmin(address newAdmin) external {
        require(newAdmin != address(0), "zero admin");
        admin = newAdmin;
    }

    /// SAFE: revert-style check on the parameter.
    function setTreasury(address newTreasury) external {
        if (newTreasury == address(0)) {
            revert("zero treasury");
        }
        treasury = payable(newTreasury);
    }

    /// SAFE: non-address parameters need no zero check.
    function setThreshold(uint256 newThreshold) external {
        threshold = newThreshold;
    }
}

/// SAFE: an abstract contract's constructor only runs through a concrete
/// derived one (whose own parameters are what need validating), so it is
/// not flagged even though it stores an unchecked parameter.
abstract contract AbstractVault {
    address internal store;

    constructor(address initial) {
        store = initial;
    }
}
