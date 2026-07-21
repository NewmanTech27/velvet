// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// Original fixture: transferFrom with a caller-chosen from address.
contract AirDropper {
    /// VULNERABLE: spends anyone's allowance, not just the caller's.
    function forward(IERC20 token, address holder, uint256 amount) external {
        token.transferFrom(holder, msg.sender, amount);
    }
}
