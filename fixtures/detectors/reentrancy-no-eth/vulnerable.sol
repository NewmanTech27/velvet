// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBurnable {
    function burn(uint256 amount) external;
}

/// Original fixture: reentrancy without Ether movement.
contract TokenAuction {
    bool public settled;
    mapping(address => uint256) public bids;

    function bid() external {
        bids[msg.sender] += 1;
    }

    /// VULNERABLE: one-shot flag set only after the external call.
    function settle(address token, uint256 amount) external {
        require(!settled, "already settled");
        (bool ok, ) = token.call(
            abi.encodeWithSignature("burn(uint256)", amount)
        );
        require(ok, "burn failed");
        settled = true;
    }

    /// VULNERABLE: high-level call before accounting update.
    function settleTyped(IBurnable token, uint256 amount) external {
        require(!settled, "already settled");
        token.burn(amount);
        settled = true;
    }
}
