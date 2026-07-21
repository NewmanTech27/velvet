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

/// Original fixture: return values of pure/view calls silently dropped.
contract Calc {
    using Math for uint256;

    IPriceFeed public feed;

    /// VULNERABLE: the computation is a no-op; v is returned unchanged.
    function run(uint256 v) external pure returns (uint256) {
        v.twice();
        return v;
    }

    /// VULNERABLE: the external view call's result is discarded.
    function refresh() external view returns (uint256) {
        feed.latestPrice();
        return 0;
    }
}
