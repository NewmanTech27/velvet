// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: every modifier path executes `_` or reverts.
contract SafeGate {
    address public owner = msg.sender;
    bool public open;

    /// SAFE: unauthorized callers revert.
    modifier onlyOwner() {
        require(msg.sender == owner, "auth");
        _;
    }

    /// SAFE: both branches either execute `_` or revert.
    modifier whenOpen() {
        if (open) {
            _;
        } else {
            revert("closed");
        }
    }

    /// SAFE: post-check after the placeholder; still every path sees `_`.
    modifier tally(uint256 expected) {
        _;
        require(expected > 0, "empty");
    }

    function sensitive() external onlyOwner returns (uint256) {
        return 42;
    }

    function guarded() external whenOpen returns (uint256) {
        return 7;
    }

    function counted() external tally(1) returns (uint256) {
        return 1;
    }
}
