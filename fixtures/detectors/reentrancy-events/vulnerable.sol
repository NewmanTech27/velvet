// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: events emitted after re-enterable calls.
contract EpochCounter {
    uint256 public epoch;

    event EpochAdvanced(uint256 epoch);
    event EpochSummary(uint256 epoch, uint256 doubled);

    /// VULNERABLE: event value depends on state that re-entry can change.
    function advance(address callback) external {
        epoch += 1;
        (bool ok, ) = callback.call("");
        require(ok, "callback failed");
        emit EpochAdvanced(epoch);
    }

    /// VULNERABLE: value re-read from state after the interaction.
    function advanceTwice(address callback) external {
        epoch += 1;
        (bool ok, ) = callback.call("");
        require(ok, "callback failed");
        emit EpochSummary(epoch, epoch * 2);
    }
}
