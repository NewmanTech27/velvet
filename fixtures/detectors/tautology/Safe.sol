// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: comparisons whose outcome depends on the value.
contract SafeAuction {
    /// SAFE: bid can be below 100 — a real check.
    function checkBid(uint256 bid) external pure returns (bool) {
        require(bid >= 100);
        return true;
    }

    /// SAFE: uint8 can exceed 200 — outcome depends on the value.
    function smallEnough(uint8 value) external pure returns (bool) {
        return value < 200;
    }

    /// SAFE: int8 ranges to 127 — the comparison can go either way.
    function tooBig(int8 delta) external pure returns (bool) {
        return delta > 100;
    }

    /// SAFE: folded bound 2**255 is inside uint256's range — not constant.
    function belowMid(uint256 x) external pure returns (bool) {
        return x < 2**255;
    }

    /// SAFE: equality against an in-range constant is a real check.
    function isMax(uint16 x) external pure returns (bool) {
        return x == 0xFFFF;
    }
}
