// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library Accounting {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}

/// Original fixture: pull-over-push payouts; loops contain no external calls.
contract PullDividends {
    using Accounting for uint256;

    mapping(address => uint256) public owed;

    /// SAFE: the loop only does accounting; no external call inside.
    function accrue(address[] calldata shareholders, uint256 amount) external {
        for (uint256 i = 0; i < shareholders.length; i++) {
            owed[shareholders[i]] = owed[shareholders[i]].add(amount);
        }
    }

    /// SAFE: a library call inside a loop is not an external call.
    function sum(uint256[] calldata values) external pure returns (uint256 total) {
        for (uint256 i = 0; i < values.length; i++) {
            total = values[i].add(total);
        }
    }

    /// SAFE: each recipient pulls their own funds (single call, no loop).
    function withdraw() external {
        uint256 amount = owed[msg.sender];
        owed[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}
