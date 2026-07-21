// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: state-variable accumulation and msg.value in loops.
contract Summer {
    uint256 public total;

    /// VULNERABLE: total is SLOAD+SSTORE on every iteration.
    function accumulate(uint256[] calldata xs) external {
        for (uint256 i = 0; i < xs.length; i++) {
            total += xs[i];
        }
    }

    /// VULNERABLE: msg.value is re-read on every iteration.
    function payEach(uint256[] calldata xs) external payable {
        for (uint256 i = 0; i < xs.length; i++) {
            if (msg.value > xs[i]) {
                total += 1;
            }
        }
    }
}
