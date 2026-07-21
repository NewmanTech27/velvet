// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: public functions that are never called internally.
contract Token {
    uint256 internal supply;

    /// VULNERABLE: only ever called by EOAs/other contracts.
    function mint(uint256 amount) public {
        supply += amount;
    }

    /// VULNERABLE: another public-only entry point.
    function burn(uint256 amount) public {
        supply -= amount;
    }

    function _move(uint256 amount) internal {
        supply = amount;
    }
}
