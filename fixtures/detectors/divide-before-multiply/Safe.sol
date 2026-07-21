// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// SAFE fixture: multiply before dividing; intentional round-down only.
contract SafeRewards {
    /// SAFE: multiply first, divide last — full precision kept.
    function reward(uint256 principal, uint256 daysStaked) external pure returns (uint256) {
        return principal * daysStaked / 365;
    }

    /// SAFE: (x / y) * y is the intentional round-down-to-multiple idiom.
    function roundDown(uint256 amount, uint256 unit) external pure returns (uint256) {
        return (amount / unit) * unit;
    }

    /// SAFE: division without a downstream multiplication.
    function average(uint256 total, uint256 count) external pure returns (uint256) {
        return total / count;
    }
}
