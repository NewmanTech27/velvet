// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: a mutex recognized at the *deepest* level of the
/// inlining chain must still suppress the interaction.
contract DeepMutexVault {
    mapping(address => uint256) public balances;
    bool private locked;

    /// SAFE: the call (three hops down) is guarded by `locked`.
    function ping() external {
        _hop1();
        balances[msg.sender] = 1;
    }

    function _hop1() internal {
        _hop2();
    }

    function _hop2() internal {
        _guarded();
    }

    function _guarded() internal {
        require(!locked, "reentrant");
        locked = true;
        (bool ok, ) = msg.sender.call("");
        require(ok, "call failed");
        locked = false;
    }
}
