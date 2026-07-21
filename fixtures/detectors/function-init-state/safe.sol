// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: literal, constant-derived and pure-call initializers.
contract SafeConfig {
    uint256 public constant FACTOR = 2;
    uint256 public base = computePure(); // SAFE: pure function
    uint256 public scaled = FACTOR * 100; // SAFE: reads a compile-time constant
    uint256 public plain = 42; // SAFE: literal

    function computePure() public pure returns (uint256) {
        return 200;
    }
}
