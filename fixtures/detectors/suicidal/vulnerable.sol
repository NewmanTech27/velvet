// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: unprotected selfdestruct entry points.
contract ArcadeMachine {
    address payable public owner;
    uint256 public highScore;

    constructor() {
        owner = payable(msg.sender);
    }

    /// VULNERABLE: anyone can destroy the contract directly.
    function resetMachine() external {
        highScore = 0;
        selfdestruct(payable(msg.sender));
    }

    /// VULNERABLE: destruction hidden behind an unprotected helper.
    function shutdown() external {
        _teardown();
    }

    function _teardown() internal {
        selfdestruct(owner);
    }
}
