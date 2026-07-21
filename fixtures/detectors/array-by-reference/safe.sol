// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: explicit storage references (mutations propagate) and
/// by-value parameters that are only read (copy is intended).
contract SafeRegistry {
    uint256[2] public slots;

    function init() external {
        bumpStorage(slots); // SAFE: storage reference, mutation propagates
        uint256 total = sum(slots); // SAFE: read-only copy
        slots[1] = total;
    }

    function bumpStorage(uint256[2] storage arr) internal {
        arr[0] += 1;
    }

    function sum(uint256[2] memory arr) internal pure returns (uint256) {
        return arr[0] + arr[1];
    }
}
