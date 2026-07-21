// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Original fixture: ternary lowering into IF/ENDIF subgraphs.

contract Ternary {
    function max(uint256 a, uint256 b) external pure returns (uint256) {
        uint256 best = a > b ? a : b;
        return best;
    }

    function floor(int256 x) external pure returns (int256) {
        int256 result = x < 0 ? (x < -100 ? -100 : x) : x;
        return result;
    }

    function pick(bool flag, uint256 a, uint256 b) external pure returns (uint256) {
        return flag ? a : b;
    }
}
