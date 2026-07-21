// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: msg.value is read once outside the loop (bounded
/// per-iteration share) or replaced by an explicit amounts array.
contract FairSplitter {
    mapping(address => uint256) public credit;

    /// SAFE: msg.value is read outside the loop into a bounded share.
    function fund(address[] calldata receivers) external payable {
        uint256 share = msg.value / receivers.length;
        for (uint256 i = 0; i < receivers.length; i++) {
            credit[receivers[i]] += share;
        }
    }

    /// SAFE: explicit per-recipient amounts checked against msg.value.
    function fundExact(address[] calldata receivers, uint256[] calldata amounts)
        external
        payable
    {
        require(receivers.length == amounts.length, "length mismatch");
        uint256 total = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            total += amounts[i];
        }
        require(total == msg.value, "sum mismatch");
        for (uint256 i = 0; i < receivers.length; i++) {
            credit[receivers[i]] += amounts[i];
        }
    }

    receive() external payable {}
}
