// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: hard-to-read long digit literals.
contract Presale {
    // VULNERABLE: 21 digits — 100e18? hard to verify by eye.
    uint256 public constant CAP = 100000000000000000000;

    // VULNERABLE: 8 digits — ambiguous magnitude.
    uint256 public constant RATE = 10000000;

    /// VULNERABLE: a long literal in function logic too.
    function quota() external pure returns (uint256) {
        return 50000000000000000000;
    }

    /// VULNERABLE: 32-hex-digit masks are as error-prone as long decimals.
    function mask(uint128 value) external pure returns (uint256) {
        return (uint256(value) & 0xFFFFFFFF00000000FFFFFFFF00000000) >> 32;
    }
}
