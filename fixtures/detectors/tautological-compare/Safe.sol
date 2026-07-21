// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: comparisons of genuinely distinct expressions.
contract SafeLimits {
    uint256 public cap;

    /// SAFE: two different variables.
    function valid(uint256 amount) external view returns (bool) {
        return amount <= cap;
    }

    /// SAFE: structurally different sides.
    function balanced(uint256 a, uint256 b, uint256 c) external pure returns (bool) {
        return a + b == a + c;
    }

    /// SAFE: distinct operands in both comparisons.
    function within(uint256 x, uint256 lo, uint256 hi) external pure returns (bool) {
        return x >= lo && x <= hi;
    }

    /// SAFE: safe-cast round-trip check.  A narrowing conversion is not a
    /// value-preserving copy, so comparing the downcasted value with the
    /// original is a genuine guard, not a tautology.
    function toUint104(uint256 value) external pure returns (uint104) {
        require(value <= type(uint104).max, "overflow");
        uint104 downcasted = uint104(value);
        require(downcasted == value, "roundtrip");
        return downcasted;
    }
}
