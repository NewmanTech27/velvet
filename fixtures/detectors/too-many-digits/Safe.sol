// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: readable literals via suffixes, notation, separators.
contract Presale {
    // SAFE: ether suffix makes the magnitude explicit.
    uint256 public constant CAP = 100 ether;

    // SAFE: scientific notation.
    uint256 public constant RATE = 1e7;

    // SAFE: digit separators.
    uint256 public constant SUPPLY = 100_000_000;

    // SAFE: short literals need no separators.
    uint256 public constant DECIMALS = 18;

    /// SAFE: readable forms inside function logic as well.
    function quota() external pure returns (uint256) {
        return 50 ether + 1_000;
    }

    /// SAFE: short hex literals (an interface id, a 64-bit mask) are
    /// reviewable as-is.
    function ids(bytes4 interfaceId, uint64 value) external pure returns (bool) {
        return interfaceId == 0xd0017968 && value == 0xffffffffffffffff;
    }
}
