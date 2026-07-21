// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: a function with cyclomatic complexity above the threshold.
contract Dispatcher {
    /// VULNERABLE: 11 decision points + 1 = complexity 12+.
    function route(uint256 op, uint256 a, uint256 b) external pure returns (uint256 r) {
        r = 0;
        if (op == 0) { r = a + b; } else { r = a; }
        if (op == 1) { r = r + 1; }
        if (op == 2) { r = r + 2; }
        if (op == 3) { r = r + 3; }
        if (op == 4) { for (uint256 i = 0; i < a; i++) { r ^= a; } }
        if (op == 5 && a > 0) { while (a > 1) { a >>= 1; r++; } }
        if (op == 6) { r = r * 2; }
        if (op == 7) { r = r * 3; }
        if (op == 8) { r = r + b; }
        if (op == 9) { r = r - 1; }
        if (op == 10) { r = r ^ b; }
    }
}
