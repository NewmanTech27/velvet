// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: own public state read through an external self-call.
contract Ledger {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    /// VULNERABLE: this.balanceOf(...) performs a STATICCALL to itself.
    function myBalance() external view returns (uint256) {
        return this.balanceOf(msg.sender);
    }

    /// VULNERABLE: plain getter through this as well.
    function supply() external view returns (uint256) {
        return this.totalSupply();
    }
}
