// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: every intermediate write is read before being overwritten.
contract SafePricing {
    uint256 public lastFee;

    /// SAFE: the first write is returned on one path.
    function quote(bool partner) external pure returns (uint256 fee) {
        fee = 100;
        if (partner) {
            fee = 80;
        }
    }

    /// SAFE: the first write is read before the second.
    function setFee(uint256 a, uint256 b) external {
        lastFee = a;
        lastFee = lastFee + b;
    }

    /// SAFE: declaration default later overwritten is an idiom.
    function clamp(uint256 x, bool positive) external pure returns (uint256) {
        uint256 result = 0;
        if (positive) {
            result = x;
        }
        return result;
    }

    /// SAFE: loop induction variable is read by the condition each round.
    function sum(uint256 n) external pure returns (uint256 total) {
        for (uint256 i = 0; i < n; i++) {
            total += i;
        }
    }
}
