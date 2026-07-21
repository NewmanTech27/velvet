// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: delegatecall to caller-controllable destinations.
contract Router {
    address public admin;
    address public module;

    constructor() {
        admin = msg.sender;
    }

    /// Anyone can set the module -> delegatecall destination is arbitrary.
    function setModule(address newModule) external {
        module = newModule;
    }

    /// VULNERABLE: user-chosen code runs in this contract's context.
    function exec(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok);
    }

    /// VULNERABLE: destination read from state anyone can set.
    function execModule(bytes calldata data) external {
        (bool ok, ) = module.delegatecall(data);
        require(ok);
    }
}
