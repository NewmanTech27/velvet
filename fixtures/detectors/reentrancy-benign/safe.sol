// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: counters updated before interacting.
contract SafeTracker {
    uint256 public totalCalls;
    mapping(address => uint256) public pings;

    /// SAFE: effect before interaction.
    function ping(address target) external {
        totalCalls += 1;
        (bool ok, ) = target.call("");
        require(ok, "ping failed");
    }

    /// SAFE: no state write after the call at all.
    function pingQuiet(address target) external {
        (bool ok, ) = target.call("");
        require(ok, "ping failed");
    }
}
