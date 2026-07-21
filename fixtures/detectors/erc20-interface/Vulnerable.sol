// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: ERC-20-named functions with wrong return types.
contract BrokenToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// VULNERABLE: ERC-20 requires `returns (bool)`; this returns nothing.
    function transfer(address to, uint256 amount) external {
        // ... move balances ...
    }

    /// VULNERABLE: approve must return bool, not uint256.
    function approve(address spender, uint256 amount) external returns (uint256) {
        return amount;
    }

    /// VULNERABLE: totalSupply must return uint256, not bool.
    function totalSupply() external pure returns (bool) {
        return true;
    }
}
