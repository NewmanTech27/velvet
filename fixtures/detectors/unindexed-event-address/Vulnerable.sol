// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: address-bearing event with no indexed parameter.
contract Registry {
    /// VULNERABLE: no parameter is indexed, so logs cannot be filtered
    /// by the user address.
    event UserRegistered(address user, uint256 id);

    function register(uint256 id) external {
        emit UserRegistered(msg.sender, id);
    }
}
