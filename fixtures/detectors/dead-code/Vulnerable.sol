// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: internal routines never called from any entry point.
contract Engine {
    function run(uint256 x) external pure returns (uint256) {
        return x + 1;
    }

    /// VULNERABLE: never called from anywhere.
    function oldHash(bytes memory data) internal pure returns (bytes32) {
        return keccak256(data);
    }

    /// VULNERABLE: only called by oldHash, which is itself dead.
    function legacyHelper(uint256 y) internal pure returns (uint256) {
        return y * 2 + uint256(oldHash(bytes("seed"))) % 7;
    }
}
