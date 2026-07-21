// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: address parameters stored without zero validation.
contract TeamWallet {
    address public admin;
    address payable public treasury;
    address public pendingAdmin;

    /// VULNERABLE: constructor parameter stored without zero validation.
    constructor(address foundation) {
        admin = msg.sender;
        treasury = payable(foundation);
    }

    /// VULNERABLE: no address(0) validation on the parameter.
    function setAdmin(address newAdmin) external {
        admin = newAdmin;
    }

    /// VULNERABLE: stored after a payable() transformation, still unchecked.
    function setTreasury(address newTreasury) external {
        treasury = payable(newTreasury);
    }

    /// VULNERABLE: two address params, only one is validated.
    function rotate(address oldAdmin, address newAdmin) external {
        require(oldAdmin == admin, "unknown");
        pendingAdmin = newAdmin;
    }
}
