// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: state read directly; this is only used for a real
/// external function call.
contract Ledger {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    /// SAFE: direct storage read.
    function myBalance() external view returns (uint256) {
        return balanceOf[msg.sender];
    }

    /// SAFE: direct storage read.
    function supply() external view returns (uint256) {
        return totalSupply;
    }

    /// SAFE: this.<function>() is an external call to a function, not a
    /// state-variable getter read.
    function render() external view returns (uint256) {
        return this.compute(totalSupply);
    }

    function compute(uint256 x) external pure returns (uint256) {
        return x * 2;
    }
}
