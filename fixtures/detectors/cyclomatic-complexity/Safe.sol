// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: small functions under the complexity threshold.
contract Dispatcher {
    /// SAFE: a single branch is complexity 2 at most.
    function double(uint256 a) external pure returns (uint256) {
        if (a > 0) {
            return a * 2;
        }
        return a;
    }

    /// SAFE: a couple of branches stay well below the threshold.
    function clamp(uint256 a, uint256 hi) external pure returns (uint256) {
        if (a > hi) {
            return hi;
        }
        if (a == 0) {
            return 1;
        }
        return a;
    }
}
