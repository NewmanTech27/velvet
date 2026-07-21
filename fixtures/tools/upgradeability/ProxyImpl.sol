// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "./Initializable.sol";

/// @notice Implementation contract used for the proxy-side checks.
contract ProxyImpl is Initializable {
    address public implementation;
    address public admin;
    uint256 public balance;

    uint256[47] private __gap;

    function initialize(address newAdmin) external initializer {
        admin = newAdmin;
    }

    /// @dev 4-byte selector 0x42966c68 — collides with the proxy's
    /// collate_propagate_storage(bytes16) (a documented selector pair).
    function burn(uint256 amount) external {
        balance -= amount;
    }

    function mint(uint256 amount) external {
        balance += amount;
    }
}
