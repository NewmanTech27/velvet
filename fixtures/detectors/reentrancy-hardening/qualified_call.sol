// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: a base-qualified static call (`Base.f()`) compiles to
/// an internal jump; its external calls must be inlined like any internal
/// call, and virtual dispatch must resolve to the most-derived override.
contract PayoutBase {
    mapping(address => uint256) public balances;

    function settle() public {
        (bool ok, ) = msg.sender.call("");
        require(ok, "call failed");
    }

    function _update(uint256 value) internal virtual {
        _settleInner(value);
    }

    function _settleInner(uint256 value) internal virtual {
        // Base hook does nothing; overrides may perform calls.
    }
}

contract QualifiedVault is PayoutBase {
    /// VULNERABLE (no-eth): the external call is reached through the
    /// base-qualified static call `PayoutBase.settle()`.
    function ping(uint256 amount) external {
        uint256 current = balances[msg.sender];
        PayoutBase.settle();
        balances[msg.sender] = amount;
    }
}

contract OverrideVault is PayoutBase {
    function _settleInner(uint256 value) internal override {
        // Most-derived override: the call lives here, not in the base.
        (bool ok, ) = msg.sender.call("");
        require(ok, "call failed");
    }

    /// VULNERABLE (no-eth): `_settleInner` is statically bound to the base
    /// version, but virtual dispatch reaches this override's call.
    function poke(uint256 value) external {
        uint256 current = balances[msg.sender];
        _update(value);
        balances[msg.sender] = value;
    }
}
