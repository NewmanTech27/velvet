// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: tx.origin authorization patterns.
contract TxOriginWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /// VULNERABLE: tx.origin used for authorization.
    function emergencyDrain(address payable to) external {
        require(tx.origin == owner, "not owner");
        to.transfer(address(this).balance);
    }

    /// VULNERABLE: tx.origin checked in a modifier.
    modifier onlyOrigin() {
        require(tx.origin == owner, "not owner");
        _;
    }

    function drainViaModifier(address payable to) external onlyOrigin {
        to.transfer(1);
    }

    /// SAFE: msg.sender used instead.
    function safeDrain(address payable to) external {
        require(msg.sender == owner, "not owner");
        to.transfer(address(this).balance);
    }
}
