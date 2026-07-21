// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: initializable logic contract left open on the
/// implementation (no locking constructor, destructive path present).
contract VaultLogicV1 {
    address public owner;
    bool public initialized;
    mapping(address => uint256) public deposits;

    /// VULNERABLE: callable on the implementation by anyone (once).
    function initialize() external {
        require(!initialized, "already initialized");
        initialized = true;
        owner = msg.sender;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    /// Destructive path reachable after the takeover.
    function upgradeToAndDestroy(address payable newImpl) external {
        require(msg.sender == owner, "not owner");
        selfdestruct(newImpl);
    }
}
