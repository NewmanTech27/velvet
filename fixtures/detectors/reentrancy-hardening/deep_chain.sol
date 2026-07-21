// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: reentrancy through a multi-level internal call chain
/// (public wrapper -> internal hops -> external call), plus an
/// state-dependent event emitted after the call inside a nested helper.
contract DeepChainVault {
    mapping(address => uint256) public balances;
    uint256 public epoch;
    event EpochAdvanced(uint256 epoch);

    /// VULNERABLE (no-eth): the external call sits three internal hops
    /// deep, and `balances` is written after it while being read before.
    function ping(uint256 amount) external {
        uint256 current = balances[msg.sender];
        _hop1(current);
        balances[msg.sender] = amount;
    }

    function _hop1(uint256 value) internal {
        _hop2(value);
    }

    function _hop2(uint256 value) internal {
        _hop3(value);
    }

    function _hop3(uint256 value) internal {
        (bool ok, ) = msg.sender.call("");
        require(ok, "call failed");
    }

    /// VULNERABLE (events): a state-dependent event is emitted after the
    /// call, inside a nested helper two levels down.
    function advance() external {
        _wrap();
    }

    function _wrap() internal {
        _advanceInner();
    }

    function _advanceInner() internal {
        _poke();
        emit EpochAdvanced(epoch);
    }

    function _poke() internal {
        (bool ok, ) = msg.sender.call("");
        require(ok, "call failed");
    }
}
