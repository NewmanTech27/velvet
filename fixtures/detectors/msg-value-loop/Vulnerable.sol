// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: msg.value read inside loop bodies in payable functions.
contract Splitter {
    mapping(address => uint256) public credit;

    /// VULNERABLE: the same msg.value is credited once per receiver.
    function fund(address[] calldata receivers) external payable {
        for (uint256 i = 0; i < receivers.length; i++) {
            credit[receivers[i]] += msg.value;
        }
    }

    /// VULNERABLE: the full msg.value is sent on every iteration.
    function payout(address payable[] calldata receivers) external payable {
        uint256 i = 0;
        while (i < receivers.length) {
            receivers[i].transfer(msg.value);
            i++;
        }
    }

    receive() external payable {}
}
