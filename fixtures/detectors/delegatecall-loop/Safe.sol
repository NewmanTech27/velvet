// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// SAFE fixture: no payable function delegatecalls inside a loop.
contract SafeMulticall {
    mapping(address => uint256) public balances;

    /// SAFE: not payable, so msg.value cannot be re-spent per iteration.
    function batch(bytes[] calldata calls) external {
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, ) = address(this).delegatecall(calls[i]);
            require(ok);
        }
    }

    /// SAFE: payable loop without any delegatecall.
    function batchDeposit(uint256 count) external payable {
        require(count > 0, "empty");
        for (uint256 i = 0; i < count; i++) {
            balances[msg.sender] += msg.value / count;
        }
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
