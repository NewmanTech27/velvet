// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: broken mutex — the guard *check* runs only after the
/// external call, so a re-entrant execution never meets it.  MUST flag.
contract LateCheckVault {
    mapping(address => uint256) public balances;
    bool private locked;

    /// VULNERABLE: the check comes after the interaction (too late), and
    /// the balance is zeroed after the call as well.
    function withdraw() external {
        locked = true;
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        require(!locked, "reentrant call"); // broken: checked too late
        balances[msg.sender] = 0;
        locked = false;
    }
}

/// Original fixture: broken mutex — the lock writes the *unlocked* value,
/// so the (correctly placed) check still passes on re-entry.  MUST flag.
contract WrongValueVault {
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    mapping(address => uint256) public balances;
    uint256 private _status = NOT_ENTERED;

    /// VULNERABLE: `_status` is set to NOT_ENTERED before the call instead
    /// of ENTERED — the mutex never engages.
    function withdraw() external {
        require(_status != ENTERED, "reentrant call");
        _status = NOT_ENTERED; // broken: should be ENTERED
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
        _status = NOT_ENTERED;
    }
}
