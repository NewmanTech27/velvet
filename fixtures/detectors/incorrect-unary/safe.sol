// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: compound assignments and spaced unary values.
contract SafeTally {
    int256 public count;

    function dec() external {
        count -= 1; // SAFE: compound assignment
    }

    function reset() external {
        count = -1; // SAFE: spaced, plainly an assignment of -1
    }

    function set() external {
        count = count - 1; // SAFE: explicit subtraction
    }
}
