// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// Original fixture: transfer/transferFrom return values ignored.
contract Staking {
    mapping(address => uint256) public stake;

    /// VULNERABLE: a silently failing transfer looks successful.
    function unstake(IERC20 token, uint256 amount) external {
        stake[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }

    /// VULNERABLE: unchecked transferFrom return value.
    function pull(IERC20 token, uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        stake[msg.sender] += amount;
    }
}
