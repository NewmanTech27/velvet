// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IToken {
    function balanceOf(address who) external view returns (uint256);
}

/// Original fixture: range comparisons for balance thresholds.
contract SafeCrowdfund {
    uint256 public constant GOAL = 100 ether;
    IToken public token;

    /// SAFE: >= tolerates forced Ether.
    function finalize() external view returns (bool) {
        return address(this).balance >= GOAL;
    }

    /// SAFE: strict equality on a plain counter, not a balance.
    function noDeposits(uint256 counter) external pure returns (bool) {
        return counter == 0;
    }

    /// SAFE: range check on the token balance.
    function hasFunds(address account) external view returns (bool) {
        return token.balanceOf(account) > 0;
    }

    receive() external payable {}
}
