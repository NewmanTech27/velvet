// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Original fixture: for/while/do-while loops with break and continue.

contract Loops {
    function sumFirst(uint256 limit) external pure returns (uint256 total) {
        for (uint256 i = 1; i <= limit; i++) {
            if (i > 100) {
                break;
            }
            total += i;
        }
    }

    function countdown(uint256 start) external pure returns (uint256 steps) {
        uint256 remaining = start;
        while (remaining > 0) {
            if (remaining == 5) {
                remaining = 0;
                continue;
            }
            remaining -= 1;
            steps += 1;
        }
    }

    function halve(uint256 x) external pure returns (uint256 count) {
        if (x == 0) {
            return 0;
        }
        do {
            x /= 2;
            count += 1;
        } while (x > 0);
    }
}
