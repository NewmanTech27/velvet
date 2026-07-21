// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface ILegacyToken {
    /// USDT-style: returns nothing at all (no boolean to check).
    function transfer(address to, uint256 amount) external;
}

/// SAFE fixture: transfer results are validated (or absent).
contract SafeStaking {
    mapping(address => uint256) public stake;

    /// SAFE: return value required inline.
    function unstake(IERC20 token, uint256 amount) external {
        stake[msg.sender] -= amount;
        require(token.transfer(msg.sender, amount), "transfer failed");
    }

    /// SAFE: return value captured, then validated.
    function unstakeCapture(IERC20 token, uint256 amount) external {
        stake[msg.sender] -= amount;
        bool ok = token.transfer(msg.sender, amount);
        require(ok, "transfer failed");
    }

    /// SAFE: no boolean is returned, so there is nothing to check.
    function unstakeLegacy(ILegacyToken token, uint256 amount) external {
        stake[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
