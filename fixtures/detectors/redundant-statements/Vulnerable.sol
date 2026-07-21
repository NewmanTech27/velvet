// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: statements with no side effects.
contract Draft {
    /// VULNERABLE: four no-op statements (type name, contract name,
    /// literal, and a pure expression whose value is dropped).
    function f(uint256 x) external pure returns (uint256) {
        uint256;
        Draft;
        42;
        x + 1;
        return x;
    }
}
