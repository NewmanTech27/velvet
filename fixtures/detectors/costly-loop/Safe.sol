// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: local accumulator and a single storage write-back.
contract Summer {
    uint256 public total;

    /// SAFE: accumulate in a local, write to storage once after the loop.
    function accumulate(uint256[] calldata xs) external {
        uint256 acc = total;
        for (uint256 i = 0; i < xs.length; i++) {
            acc += xs[i];
        }
        total = acc;
    }

    /// SAFE: msg.value is read once into a local before the loop.
    function payEach(uint256[] calldata xs) external payable {
        uint256 paid = msg.value;
        uint256 acc = total;
        for (uint256 i = 0; i < xs.length; i++) {
            if (paid > xs[i]) {
                acc += 1;
            }
        }
        total = acc;
    }
}
