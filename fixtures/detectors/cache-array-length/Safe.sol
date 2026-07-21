// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: array length cached / iterated over memory.
contract Registry {
    uint256[] public ids;

    /// SAFE: the length is cached in a local before the loop.
    function sum() external view returns (uint256 s) {
        uint256 n = ids.length;
        for (uint256 i = 0; i < n; i++) {
            s += ids[i];
        }
    }

    /// SAFE: iterating a calldata/memory array costs no per-iteration SLOAD.
    function sumOf(uint256[] calldata values) external pure returns (uint256 s) {
        for (uint256 i = 0; i < values.length; i++) {
            s += values[i];
        }
    }
}
