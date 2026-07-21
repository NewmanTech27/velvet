// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Original fixture: if/else joins, else-if chains, ENDIF pruning.

contract Branching {
    uint256 private value;

    function classify(int256 x) external pure returns (uint256) {
        uint256 result;
        if (x < 0) {
            result = 0;
        } else if (x < 10) {
            result = 1;
        } else {
            result = 2;
        }
        return result;
    }

    function sign(int256 x) external pure returns (int256) {
        if (x < 0) {
            return -1;
        } else {
            return 1;
        }
    }

    function touch(uint256 v) external {
        if (v > 0) {
            value = v;
        }
    }

    function deadAfterBothReturn(int256 x) external pure returns (int256) {
        if (x < 0) {
            return -1;
        } else {
            return 1;
        }
        // never reached: both branches above return
        return 0;
    }
}
