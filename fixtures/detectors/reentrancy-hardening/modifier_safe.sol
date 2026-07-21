// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: checks-effects-interactions *through* a modifier —
/// the effect (write) runs in the modifier before `_`, the interaction in
/// the body afterwards.
contract SafeModifierVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    modifier zeroFirst() {
        balances[msg.sender] = 0;
        _;
    }

    /// SAFE: the balance is zeroed (in the modifier) before the call.
    function withdraw() external zeroFirst {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }
}

/// Post-`_` modifier code runs *after* the body: an interaction there with
/// no later write anywhere is safe.
contract SafePostModifier {
    bool public settled;

    modifier notifyAfter(address target) {
        _;
        (bool ok, ) = target.call("");
        require(ok, "notify failed");
    }

    /// SAFE: the flag is set in the body, before the modifier's post-`_`
    /// external call.
    function settle(address target) external notifyAfter(target) {
        settled = true;
    }
}
