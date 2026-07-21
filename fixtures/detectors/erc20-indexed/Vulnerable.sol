// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: ERC-20 events missing indexed address parameters.
contract Token {
    /// VULNERABLE: neither from nor to is indexed.
    event Transfer(address from, address to, uint256 value);

    /// VULNERABLE: spender is not indexed (owner is).
    event Approval(address indexed owner, address spender, uint256 value);

    mapping(address => uint256) public balanceOf;

    function transfer(address to, uint256 amount) external returns (bool) {
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
