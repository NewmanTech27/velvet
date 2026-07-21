// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IToken {
    function balanceOf(address account) external view returns (uint256);
}

interface IPayer {
    function pay(uint256 amount) external;
}

/// Original fixture: the balance delta check after a re-enterable call
/// validates against a snapshot the re-entry can make stale.
contract Minter {
    uint256 public totalMinted;

    /// VULNERABLE: balanceOf is snapshotted, an untrusted call runs, then
    /// the delta is enforced — re-entry can inflate the balance between.
    function mint(IToken token, uint256 owed) external {
        uint256 before_ = token.balanceOf(address(this));
        IPayer(msg.sender).pay(owed);
        require(token.balanceOf(address(this)) - before_ >= owed, "underpaid");
        totalMinted += owed;
    }
}
