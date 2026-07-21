// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: the mutex covers only one of two paths (inline if) —
/// the unguarded path reaches the call without the check, so the guard
/// must NOT suppress anything.  MUST flag.
contract PartialInlineVault {
    mapping(address => uint256) public balances;
    bool private locked;

    /// VULNERABLE: with useGuard false the call is reached unlocked, and
    /// the balance is zeroed after it.
    function withdraw(bool useGuard) external {
        if (useGuard) {
            require(!locked, "reentrant call");
            locked = true;
        }
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
        if (useGuard) {
            locked = false;
        }
    }
}

/// Original fixture: same partial coverage expressed inside a modifier —
/// the check does not dominate the interaction.  MUST flag.
contract PartialModifierVault {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier maybeGuard(bool on) {
        if (on) {
            require(!locked, "reentrant call");
            locked = true;
        }
        _;
        if (on) {
            locked = false;
        }
    }

    /// VULNERABLE: with on false the body runs without the mutex.
    function withdraw(bool on) external maybeGuard(on) {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }
}
