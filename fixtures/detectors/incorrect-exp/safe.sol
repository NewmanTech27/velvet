// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: real exponentiation and real (variable) XOR.
contract SafeSale {
    uint256 public constant HARD_CAP = 1000 * 10 ** 18; // SAFE: ** used

    function big() external pure returns (uint256) {
        return 2 ** 255; // SAFE: exponentiation operator
    }

    function mix(uint256 a, uint256 b) external pure returns (uint256) {
        return a ^ b; // SAFE: XOR on non-constant operands
    }

    function mask(uint256 x) external pure returns (uint256) {
        return x ^ 0xff; // SAFE: hex literal is the bit-mask idiom
    }

    function gray(uint256 x) external pure returns (uint256) {
        return x ^ (x >> 1); // SAFE: no literal operand (Gray code)
    }
}
