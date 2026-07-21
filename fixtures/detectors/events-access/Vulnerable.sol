// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: critical role changes without any event.
contract Governed {
    address public governor;
    address public admin;

    modifier onlyGovernor() {
        require(msg.sender == governor, "auth");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "auth");
        _;
    }

    constructor() {
        governor = msg.sender;
        admin = msg.sender;
    }

    /// VULNERABLE: the governor role changes hands silently.
    function transferGovernance(address next) external onlyGovernor {
        governor = next;
    }

    /// VULNERABLE: the admin change is delegated to an internal helper
    /// that also emits nothing.
    function rotateAdmin(address next) external onlyAdmin {
        _setAdmin(next);
    }

    function _setAdmin(address next) internal {
        admin = next;
    }
}
