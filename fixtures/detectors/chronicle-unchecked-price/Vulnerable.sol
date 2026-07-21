// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original minimal mock of the Chronicle oracle interface.
interface IChronicle {
    function read() external view returns (uint256 value);
}

/// Original fixture: Chronicle read() consumed without a validity check.
contract Pricer {
    /// VULNERABLE: read() gives no validity/age signal.
    function ethUsd(IChronicle feed) external view returns (uint256) {
        return feed.read();
    }

    /// VULNERABLE: read() result feeds a downstream computation.
    function twap(IChronicle feed, uint256 factor) external view returns (uint256) {
        uint256 spot = feed.read();
        return spot * factor;
    }
}
