// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: assembly return() used where the Solidity function
/// still owns its return path.
contract Codec {
    uint256 public marker;

    /// VULNERABLE: named returns are declared but the assembly block
    /// terminates the frame; the ABI encoding of (a, b) is bypassed.
    function encode(uint256 x) external pure returns (bytes32 a, bytes32 b) {
        assembly {
            mstore(0, x)
            return(0, 64)
        }
    }

    /// VULNERABLE: the assignment after the assembly block never runs
    /// because return() terminates the frame instead of leaving.
    function tag(uint256 x) external {
        assembly {
            mstore(0, x)
            return(0, 32)
        }
        marker = x;
    }
}
