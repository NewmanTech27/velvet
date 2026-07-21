// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: first file of the inconsistent-pragma project.
contract TokenA {
    uint256 public supply;

    function mint(uint256 amount) external {
        supply += amount;
    }
}
