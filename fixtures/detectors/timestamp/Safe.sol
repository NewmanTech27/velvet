// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// SAFE fixture: the timestamp is only *recorded*, never used in a
/// comparison or condition that gates logic (catalog §7.39).
contract SafeTimed {
    uint256 public deadline;

    constructor() {
        deadline = block.timestamp + 30 days;
    }

    /// SAFE: recording a timestamp-derived value is not a comparison.
    function touch() external {
        deadline = block.timestamp + 30 days;
    }

    /// SAFE: returning a stored value performs no timestamp comparison.
    function timeLeft() external view returns (uint256) {
        return deadline;
    }
}
