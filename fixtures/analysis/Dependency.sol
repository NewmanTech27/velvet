// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: multi-transaction dependency (architecture.md §7.3).
contract MultiTx {
    uint256 a;
    uint256 b;
    uint256 c;

    function setA(uint256 input_a) external {
        a = input_a;
    }

    function setB() external {
        b = a; // b depends on input_a across transactions
    }

    function setC(uint256 input_c) external {
        c = input_c; // c is independent of input_a
    }
}
