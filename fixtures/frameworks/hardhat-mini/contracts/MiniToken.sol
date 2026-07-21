// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@minipkg/contracts/Owned.sol";

/// @notice Tiny token exercising a node_modules dependency import.
contract MiniToken is Owned {
    string public symbol = "MINI";
    mapping(address => uint256) public balanceOf;

    function mint(uint256 amount) external onlyOwner {
        balanceOf[msg.sender] += amount;
    }
}
