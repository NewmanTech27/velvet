// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBurnableSafe {
    function burn(uint256 amount) external;
}

/// Original fixture: flag set before interacting.
contract SafeAuction {
    bool public settled;
    mapping(address => uint256) public bids;

    function bid() external {
        bids[msg.sender] += 1;
    }

    /// SAFE: checks-effects-interactions.
    function settle(address token, uint256 amount) external {
        require(!settled, "already settled");
        settled = true;
        (bool ok, ) = token.call(
            abi.encodeWithSignature("burn(uint256)", amount)
        );
        require(ok, "burn failed");
    }

    /// SAFE: typed call, effect first.
    function settleTyped(IBurnableSafe token, uint256 amount) external {
        require(!settled, "already settled");
        settled = true;
        token.burn(amount);
    }
}
