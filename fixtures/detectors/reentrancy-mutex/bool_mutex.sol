// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

error Reentrancy();

/// Original fixture: boolean reentrancy mutex variants that must not be
/// flagged (modifier form, inline if-revert form, and a guard covering an
/// internal helper's external call).
contract BoolGuardedVault {
    mapping(address => uint256) public balances;
    uint256 public totalCalls;
    bool private locked;

    modifier lock() {
        require(!locked, "reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// SAFE: the Ether send precedes the balance update in shape, but the
    /// boolean mutex blocks re-entry on every path.
    function withdraw() external lock {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }

    /// SAFE (benign shape): the counter does not gate the call, but the
    /// mutex makes re-entry impossible anyway.
    function ping(address target) external lock {
        (bool ok, ) = target.call("");
        require(ok, "ping failed");
        totalCalls += 1;
    }
}

/// Original fixture: boolean mutex written inline with an if-revert guard
/// on a custom error (no modifier involved).
contract CustomErrorGuardedVault {
    mapping(address => uint256) public balances;
    bool private locked;

    /// SAFE: check, lock, interaction, effect, unlock — inline.
    function withdraw() external {
        if (locked) revert Reentrancy();
        locked = true;
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
        locked = false;
    }
}

/// Original fixture: the external call lives in an internal helper, the
/// mutex on the entry function — the guard must cover the inlined call.
contract HelperGuardedVault {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier lock() {
        require(!locked, "reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function _pay(uint256 amount) internal {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    /// SAFE: the helper's Ether send is covered by the caller's mutex.
    function withdraw() external lock {
        uint256 amount = balances[msg.sender];
        _pay(amount);
        balances[msg.sender] = 0;
    }
}
