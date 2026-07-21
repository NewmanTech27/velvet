// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: hard-coded boolean constants in conditions.
contract Bridge {
    bool public paused;
    uint256 public deposits;

    /// VULNERABLE: debug leftover — the pause check never runs.
    function deposit(uint256 amount) external {
        if (false) {
            require(!paused, "paused");
        }
        deposits += amount;
    }

    /// VULNERABLE: right side is constant — the flag is meaningless.
    function isActive(bool flag) external pure returns (bool) {
        return flag || true;
    }

    /// VULNERABLE: conjunction with false is always false.
    function eligible(uint256 score) external pure returns (bool) {
        return score > 10 && false;
    }
}
