// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: events emitted before interacting / free of state.
contract SafeEpochCounter {
    uint256 public epoch;

    event EpochAdvanced(uint256 epoch);
    event Pinged(address target);

    /// SAFE: event emitted before the external call.
    function advance(address callback) external {
        epoch += 1;
        emit EpochAdvanced(epoch);
        (bool ok, ) = callback.call("");
        require(ok, "callback failed");
    }

    /// SAFE: the event after the call depends only on the caller input,
    /// not on contract state.
    function ping(address callback) external {
        (bool ok, ) = callback.call("");
        require(ok, "callback failed");
        emit Pinged(msg.sender);
    }
}
