// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Original fixture: modifiers with their own CFGs, applied in order.

contract Guarded {
    address public owner;
    bool public locked;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier whenUnlocked() {
        if (locked) {
            revert("locked");
        }
        _;
    }

    function sensitive(uint256 amount) external onlyOwner whenUnlocked returns (bool) {
        return amount > 0;
    }
}
