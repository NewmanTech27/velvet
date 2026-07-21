// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: boolean expressions used directly.
contract Lock {
    bool public locked;
    uint256 public score;

    /// SAFE: the negation reads directly.
    function open() external view returns (bool) {
        return !locked;
    }

    /// SAFE: the comparison itself is the boolean.
    function eligible() external view returns (bool) {
        return score > 5;
    }

    /// SAFE: a plain require on the boolean.
    function deposit() external {
        require(!locked, "locked");
        score += 1;
    }
}
