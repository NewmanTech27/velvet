// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library Math {
    function twice(uint256 x) internal pure returns (uint256) {
        return x * 2;
    }
}

interface IPriceFeed {
    function latestPrice() external view returns (uint256);
}

/// Original fixture: every value-returning call's result is used.
contract SafeCalc {
    using Math for uint256;

    IPriceFeed public feed;
    uint256 public lastPrice;

    /// SAFE: the library result is returned.
    function run(uint256 v) external pure returns (uint256) {
        return v.twice();
    }

    /// SAFE: the external view result is stored.
    function refresh() external {
        lastPrice = feed.latestPrice();
    }

    /// SAFE: state-mutating calls are out of scope (their effect is the point).
    function bump(uint256 v) external returns (uint256) {
        lastPrice = v;
        return lastPrice;
    }

    function touch() external {
        this.bump(1); // mutates state; discarding its return is fine
    }
}
