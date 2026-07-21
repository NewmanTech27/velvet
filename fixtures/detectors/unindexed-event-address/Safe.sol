// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: address-bearing events index the address.
contract Registry {
    /// SAFE: the address parameter is indexed.
    event UserRegistered(address indexed user, uint256 id);

    /// SAFE: no address parameter at all.
    event CounterAdvanced(uint256 id);

    function register(uint256 id) external {
        emit UserRegistered(msg.sender, id);
        emit CounterAdvanced(id);
    }
}
