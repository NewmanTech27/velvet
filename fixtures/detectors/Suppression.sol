// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: inline suppression comments.
contract Suppression {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function suppressedNextLine() external {
        // velvet-disable-next-line tx-origin
        require(tx.origin == owner, "not owner");
    }

    // velvet-disable-start tx-origin
    function suppressedRegion() external {
        require(tx.origin == owner, "not owner");
    }
    // velvet-disable-end tx-origin

    function notSuppressed() external {
        require(tx.origin == owner, "not owner");
    }
}
