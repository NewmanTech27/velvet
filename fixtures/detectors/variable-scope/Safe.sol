// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: every local is declared (and its declaration
/// executed) before any use.
contract Scope {
    /// SAFE: declaration precedes use on every path.
    function f(bool cond) external pure returns (uint256) {
        uint256 bonus = 5;
        uint256 result = bonus + 1;
        uint256 limit = 0;
        if (cond) {
            limit = 10;
        }
        return result + limit;
    }

    /// SAFE: loop variable is declared in the loop header before use.
    function sum(uint256 n) external pure returns (uint256 total) {
        for (uint256 i = 0; i < n; i++) {
            total += i;
        }
    }
}
