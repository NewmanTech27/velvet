// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: real conditions only; idiomatic while(true) with break.
contract SafeBridge {
    bool public paused;
    uint256 public deposits;

    /// SAFE: the condition depends on state, not a literal.
    function deposit(uint256 amount) external {
        if (!paused) {
            deposits += amount;
        }
    }

    /// SAFE: no constant operand in the logical expression.
    function isActive(bool flag, bool enabled) external pure returns (bool) {
        return flag || enabled;
    }

    /// SAFE: while (true) with a structured break is a common idiom.
    function countUpTo(uint256 n) external pure returns (uint256) {
        uint256 i = 0;
        while (true) {
            i += 1;
            if (i >= n) {
                break;
            }
        }
        return i;
    }
}
