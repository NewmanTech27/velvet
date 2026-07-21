// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVault {
    function deposit(uint256 amount) external;

    function withdraw(uint256 amount) external;
}

/// Original fixture: Vault implements IVault's whole API without
/// declaring the inheritance.
contract Vault {
    mapping(address => uint256) public balances;

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
    }
}
