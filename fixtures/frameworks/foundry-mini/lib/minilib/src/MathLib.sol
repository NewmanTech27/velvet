// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Stand-in for a forge-installed dependency under lib/.
library MathLib {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}
