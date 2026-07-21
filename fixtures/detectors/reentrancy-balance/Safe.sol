// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ISafeToken {
    function balanceOf(address account) external view returns (uint256);

    function transferFrom(address from, address to, uint256 amount)
        external
        returns (bool);
}

/// Original fixture: pull payment (no balance delta around a call) and a
/// plain balance check with no snapshot/call sandwich.
contract PullMinter {
    uint256 public totalMinted;

    /// SAFE: pull the payment instead of comparing balance deltas.
    function mint(ISafeToken token, uint256 owed) external {
        require(token.transferFrom(msg.sender, address(this), owed), "pay failed");
        totalMinted += owed;
    }

    /// SAFE: a single balanceOf check with no external call in between.
    function hasFunds(ISafeToken token, uint256 owed) external view returns (bool) {
        return token.balanceOf(address(this)) >= owed;
    }
}
