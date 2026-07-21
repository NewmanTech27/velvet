// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: comparisons of an expression with itself.
contract Limits {
    uint256 public cap;

    /// VULNERABLE: always true; `cap` was meant to be compared.
    function valid(uint256 amount) external view returns (bool) {
        return amount <= amount;
    }

    /// VULNERABLE: both sides are the same pure expression.
    function balanced(uint256 a, uint256 b) external pure returns (bool) {
        return a + b == a + b;
    }

    /// VULNERABLE: always false.
    function changed(uint256 x) external pure returns (bool) {
        return x != x;
    }

    /// VULNERABLE: state variable compared with itself.
    function atCap() external view returns (bool) {
        return cap >= cap;
    }
}
