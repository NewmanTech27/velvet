// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: protected heuristic (architecture.md §7.2).
contract Guarded {
    address public owner;
    uint256 public value;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    /// protected via modifier
    function setValue(uint256 next) external onlyOwner {
        value = next;
    }

    /// protected via inline require
    function setValueInline(uint256 next) external {
        require(msg.sender == owner, "not owner");
        value = next;
    }

    /// protected via if + revert
    function setValueIf(uint256 next) external {
        if (msg.sender != owner) {
            revert("not owner");
        }
        value = next;
    }

    /// NOT protected
    function setValueOpen(uint256 next) external {
        value = next;
    }
}
