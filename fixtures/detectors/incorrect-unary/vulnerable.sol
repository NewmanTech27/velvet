// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: =- parses as assignment of a unary minus value.
contract Tally {
    int256 public count;

    function addOne() external {
        count =- 1; // VULNERABLE: sets count to -1; -= 1 was intended
    }
}
