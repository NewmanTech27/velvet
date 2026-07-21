// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: writes overwritten without an intervening read.
contract Pricing {
    uint256 public lastFee;

    /// VULNERABLE: the first write of fee is dead.
    function quote(bool partner) external pure returns (uint256 fee) {
        fee = 100;
        fee = partner ? 80 : 100;
    }

    /// VULNERABLE: the state variable is written twice without a read.
    function setFee(uint256 a, uint256 b) external {
        lastFee = a;
        lastFee = b;
    }

    /// VULNERABLE: plain local overwritten before any use.
    function discount(uint256 x) external pure returns (uint256) {
        uint256 rate = x / 2;
        rate = 10;
        return rate;
    }
}
