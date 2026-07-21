// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: implementation locked at construction, no destructive
/// path, and the initializer is authorization-gated.
contract VaultLogicV2 {
    uint64 private _initialized;
    address public owner;
    mapping(address => uint256) public deposits;

    constructor() {
        _disableInitializers();
    }

    function _disableInitializers() internal {
        _initialized = type(uint64).max;
    }

    /// SAFE: the implementation itself can never be initialized.
    function initialize() external {
        require(_initialized == 0, "locked");
        _initialized = 1;
        owner = msg.sender;
    }

    /// SAFE: authorization-gated initialization helper.
    function initializeAs(address newOwner) external {
        require(_initialized == 0, "locked");
        require(msg.sender == owner, "not owner");
        _initialized = 1;
        owner = newOwner;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }
}
