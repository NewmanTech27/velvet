// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// SAFE fixture: send() results are checked.
contract SafeRefunds {
    mapping(address => uint256) public refunds;

    /// SAFE: send result required inline.
    function refund() external {
        uint256 amt = refunds[msg.sender];
        refunds[msg.sender] = 0;
        require(payable(msg.sender).send(amt), "refund failed");
    }

    /// SAFE: send result consumed by a condition that reverts.
    function refundConditional() external {
        uint256 amt = refunds[msg.sender];
        refunds[msg.sender] = 0;
        bool ok = payable(msg.sender).send(amt);
        if (!ok) {
            refunds[msg.sender] = amt;
            revert("refund failed");
        }
    }
}
