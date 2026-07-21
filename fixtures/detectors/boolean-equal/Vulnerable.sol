// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: booleans compared to boolean literals.
contract Lock {
    bool public locked;
    uint256 public score;

    /// VULNERABLE: equivalent to `!locked`.
    function open() external view returns (bool) {
        return locked == false;
    }

    /// VULNERABLE: equivalent to `score > 5`.
    function eligible() external view returns (bool) {
        return (score > 5) == true;
    }

    /// VULNERABLE: equivalent to `require(!locked)`.
    function deposit() external {
        require(locked == false, "locked");
        score += 1;
    }
}
