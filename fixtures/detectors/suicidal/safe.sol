// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: destruction restricted to the owner.
contract GuardedMachine {
    address payable public owner;
    uint256 public highScore;

    constructor() {
        owner = payable(msg.sender);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    /// SAFE: modifier-gated destruction.
    function resetMachine() external onlyOwner {
        highScore = 0;
        selfdestruct(owner);
    }

    /// SAFE: inline msg.sender check on the entry point.
    function shutdown() external {
        require(msg.sender == owner, "not owner");
        selfdestruct(owner);
    }

    /// SAFE: helper performs its own authorization check.
    function retire() external {
        _teardown();
    }

    function _teardown() internal {
        require(msg.sender == owner, "not owner");
        selfdestruct(owner);
    }
}
