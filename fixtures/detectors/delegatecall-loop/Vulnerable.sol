// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: delegatecall inside a loop of a payable function.
contract Multicall {
    mapping(address => uint256) public balances;

    /// VULNERABLE: msg.value is re-used on every loop iteration.
    function batch(bytes[] calldata calls) external payable {
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, ) = address(this).delegatecall(calls[i]);
            require(ok);
        }
    }

    /// The delegated code path credits balances by msg.value.
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
