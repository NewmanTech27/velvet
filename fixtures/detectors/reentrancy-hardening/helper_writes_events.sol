// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: state writes and event emissions inside an internal
/// helper called *after* the external call count as after the call.
contract HelperEpoch {
    uint256 public epoch;

    event EpochAdvanced(uint256 epoch);

    function _bump() internal {
        epoch += 1;
    }

    /// VULNERABLE (benign + events): the helper's write and the event both
    /// happen after the external call.
    function advance(address callback) external {
        (bool ok, ) = callback.call("");
        require(ok, "callback failed");
        _bump();
        emit EpochAdvanced(epoch);
    }
}
