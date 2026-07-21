// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: every statement has an effect or a value consumer.
contract Finished {
    uint256 public total;

    /// SAFE: assignments, a call, and an increment all have effects.
    function f(uint256 x) external returns (uint256) {
        uint256 y = x + 1; // declaration with initializer, value consumed
        total = y; // state write
        total += 1; // compound assignment
        return this.sum(total, y); // call whose value is returned
    }

    /// SAFE: plain external call statement.
    function sum(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }
}
