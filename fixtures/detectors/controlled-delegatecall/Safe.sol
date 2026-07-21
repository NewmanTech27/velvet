// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// SAFE fixture: delegatecall only to trusted destinations.
contract SafeRouter {
    address public owner;
    address public implementation;
    address public constant FIXED_IMPL = 0x000000000000000000000000000000000000dEaD;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    /// Trusted: only the owner can set the implementation.
    function setImplementation(address newImpl) external onlyOwner {
        implementation = newImpl;
    }

    /// SAFE: destination is owner-controlled state.
    function upgrade(bytes calldata data) external onlyOwner {
        (bool ok, ) = implementation.delegatecall(data);
        require(ok);
    }

    /// SAFE: destination is a hard-coded constant address.
    function forwardToFixed(bytes calldata data) external {
        (bool ok, ) = FIXED_IMPL.delegatecall(data);
        require(ok);
    }
}
