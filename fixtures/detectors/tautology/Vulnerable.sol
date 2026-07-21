// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: comparisons fixed by the operand's type range.
contract Auction {
    /// VULNERABLE: uint256 is always >= 0 — the check is vacuous.
    function checkBid(uint256 bid) external pure returns (bool) {
        require(bid >= 0);
        return true;
    }

    /// VULNERABLE: uint8 is always < 512 — always true.
    function smallEnough(uint8 value) external pure returns (bool) {
        return value < 512;
    }

    /// VULNERABLE: uint256 is never < 0 — always false.
    function underflowed(uint256 amount) external pure returns (bool) {
        return amount < 0;
    }

    /// VULNERABLE: 0x10001 is outside the uint16 range — always false.
    function alwaysDifferent(uint16 x) external pure returns (bool) {
        return x == 0x10001;
    }
}
