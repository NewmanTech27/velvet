// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: a view function with read-only inline assembly, built
/// with a modern compiler (the constant-function attributes are enforced,
/// and the pre-0.5 bug window does not apply).
contract SafeReader {
    function codeSize(address a) external view returns (uint256 size) {
        assembly {
            size := extcodesize(a) // SAFE: read-only, and compiler >= 0.5
        }
    }
}
