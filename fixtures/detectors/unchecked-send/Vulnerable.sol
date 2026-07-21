// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: send() return value ignored.
contract Refunds {
    mapping(address => uint256) public refunds;

    /// VULNERABLE: send may fail silently; the refund is already zeroed.
    function refund() external {
        uint256 amt = refunds[msg.sender];
        refunds[msg.sender] = 0;
        payable(msg.sender).send(amt);
    }
}
