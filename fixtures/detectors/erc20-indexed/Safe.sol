// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: conforming ERC-20 events plus out-of-scope name reuse.
contract SafeToken {
    /// SAFE: both address parameters indexed, per the standard.
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    mapping(address => uint256) public balanceOf;

    function transfer(address to, uint256 amount) external returns (bool) {
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}

/// SAFE: a Transfer event with a non-ERC-20 signature is out of scope.
contract Bridge {
    event Transfer(address token, uint256 amount);

    function relay(address token, uint256 amount) external {
        emit Transfer(token, amount);
    }
}
