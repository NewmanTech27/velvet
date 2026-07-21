// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: Ether sent to caller-chosen destinations.
contract Faucet {
    address payable public beneficiary;

    function fund() external payable {}

    /// VULNERABLE: destination is a function parameter.
    function drip(address payable to, uint256 amount) external {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "send failed");
    }

    /// VULNERABLE: destination via transfer to a caller-chosen address.
    function dripTransfer(address payable to, uint256 amount) external {
        to.transfer(amount);
    }

    /// VULNERABLE: destination is a state variable anyone can set.
    function setBeneficiary(address payable who) external {
        beneficiary = who;
    }

    function dripStored(uint256 amount) external {
        beneficiary.transfer(amount);
    }
}
