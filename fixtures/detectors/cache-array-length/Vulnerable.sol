// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: storage-array length re-read each iteration.
contract Registry {
    uint256[] public ids;

    /// VULNERABLE: ids.length is an SLOAD on every iteration.
    function sum() external view returns (uint256 s) {
        for (uint256 i = 0; i < ids.length; i++) {
            s += ids[i];
        }
    }

    /// VULNERABLE: same re-read in a second loop.
    function countAbove(uint256 threshold) external view returns (uint256 n) {
        for (uint256 i = 0; i < ids.length; i++) {
            if (ids[i] > threshold) {
                n++;
            }
        }
    }
}
