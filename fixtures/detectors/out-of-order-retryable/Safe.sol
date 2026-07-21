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

/// Original fixture: dependent steps bundled into a single ticket.
contract L1Bridge {
    /// SAFE: one ticket carries the whole bundled L2 action.
    function claimAndUnstake(
        IInbox inbox,
        address l2,
        bytes calldata bundled
    ) external payable {
        inbox.createRetryableTicket(l2, 0, 0, msg.sender, msg.sender, 0, 0, bundled);
    }

    /// SAFE: two independent functions each create a single ticket.
    function unstake(IInbox inbox, address l2, bytes calldata data) external payable {
        inbox.createRetryableTicket(l2, 0, 0, msg.sender, msg.sender, 0, 0, data);
    }
}
