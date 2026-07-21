// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Unrelated contract: must be excluded by `velvet-flat --contract TokenVault`.
contract Standalone {
    uint256 public value;

    function setValue(uint256 newValue) external {
        value = newValue;
    }
}
