// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: ^ used where ** was intended.
contract Sale {
    uint256 public constant HARD_CAP = 1000 * 10 ^ 18; // VULNERABLE: 10 xor 18

    function flag() external pure returns (uint256) {
        return 2 ^ 256; // VULNERABLE: 258, not 2**256
    }

    function inverse(uint256 d) external pure returns (uint256) {
        return (3 * d) ^ 2; // VULNERABLE: decimal-literal exponent shape
    }

    function pow2(uint256 x) external pure returns (uint256) {
        return x ^ 2; // VULNERABLE: x*x intended, x xor 2 computed
    }
}
