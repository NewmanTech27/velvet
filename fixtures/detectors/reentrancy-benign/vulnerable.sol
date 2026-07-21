// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: non-gating writes after external calls.
contract CallTracker {
    uint256 public totalCalls;
    mapping(address => uint256) public pings;

    /// VULNERABLE (benign): the counter does not gate the call; re-entry is
    /// equivalent to calling ping() twice.
    function ping(address target) external {
        (bool ok, ) = target.call("");
        require(ok, "ping failed");
        totalCalls += 1;
    }

    /// VULNERABLE (benign): per-sender stats updated after the interaction
    /// and not read on the path to it.
    function pingCounted(address target) external {
        (bool ok, ) = target.call("");
        require(ok, "ping failed");
        pings[msg.sender] += 1;
        totalCalls += 1;
    }
}
