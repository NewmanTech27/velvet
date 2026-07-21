// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original minimal mock of the Arbitrum inbox interface.
interface IInbox {
    function createRetryableTicket(
        address to,
        uint256 l2CallValue,
        uint256 maxSubmissionCost,
        address excessFeeRefundAddress,
        address callValueRefundAddress,
        uint256 gasLimit,
        uint256 maxFeePerGas,
        bytes calldata data
    ) external payable returns (uint256);
}

/// Original fixture: dependent steps split across two retryable tickets.
contract L1Bridge {
    /// VULNERABLE: two tickets assumed to execute in order on L2.
    function claimThenUnstake(
        IInbox inbox,
        address l2,
        bytes calldata claim,
        bytes calldata unstake
    ) external payable {
        // claim rewards first...
        inbox.createRetryableTicket(l2, 0, 0, msg.sender, msg.sender, 0, 0, claim);
        // ...then unstake (destroys the rewards state the claim relies on).
        inbox.createRetryableTicket(l2, 0, 0, msg.sender, msg.sender, 0, 0, unstake);
    }
}
