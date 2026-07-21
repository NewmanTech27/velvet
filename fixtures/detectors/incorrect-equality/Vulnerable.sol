// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IToken {
    function balanceOf(address who) external view returns (uint256);
}

/// Original fixture: strict equality against a balance.
contract Crowdfund {
    uint256 public constant GOAL = 100 ether;
    IToken public token;

    /// VULNERABLE: forced Ether makes the equality permanently false.
    function finalize() external view returns (bool) {
        return address(this).balance == GOAL;
    }

    /// VULNERABLE: a donation of 1 wei skips the snapshot check.
    function untouched(address account) external view returns (bool) {
        return token.balanceOf(account) == 0;
    }

    /// VULNERABLE: balance cached in a local, then strictly compared.
    function exactMatch() external view returns (bool) {
        uint256 current = address(this).balance;
        return current != GOAL;
    }

    receive() external payable {}
}
