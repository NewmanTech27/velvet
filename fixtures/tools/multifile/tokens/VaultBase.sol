// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../base/Owned.sol";

contract VaultBase is Owned {
    uint256 public deposits;

    event Deposited(address indexed from, uint256 amount);

    function deposit() external payable {
        deposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }
}
