// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: modifiers with paths that skip `_` without reverting.
contract Gate {
    address public owner = msg.sender;
    bool public open;

    /// VULNERABLE: non-owners fall through; the body is silently skipped.
    modifier onlyIfOwner() {
        if (msg.sender == owner) {
            _;
        }
    }

    /// VULNERABLE: the early-return path skips `_` without reverting.
    modifier unlessClosed() {
        if (!open) {
            return;
        }
        _;
    }

    function sensitive() external onlyIfOwner returns (uint256) {
        return 42;
    }

    function guarded() external unlessClosed returns (uint256) {
        return 7;
    }
}
