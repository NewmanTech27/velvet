// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

/// @notice An upgrade-intended contract written without any Initializable
/// helper in the codebase: init-missing / init-inherited /
/// initializer-missing informational checks fire, and the unguarded
/// initialize function is flagged by missing-init-modifier.
contract NoInitPattern {
    uint256 public value;

    function initialize(uint256 newValue) external {
        value = newValue;
    }
}
