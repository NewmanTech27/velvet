// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: every critical permission change is announced.
contract SafeGoverned {
    address public governor;

    event GovernorTransferred(address indexed previous, address indexed next);

    modifier onlyGovernor() {
        require(msg.sender == governor, "auth");
        _;
    }

    constructor() {
        governor = msg.sender;
    }

    /// SAFE: the role change emits an event.
    function transferGovernance(address next) external onlyGovernor {
        emit GovernorTransferred(governor, next);
        governor = next;
    }

    /// SAFE: writing an unrelated variable needs no access event.
    uint256 public counter;

    function bump(uint256 by) external onlyGovernor {
        counter += by;
    }
}

/// Original fixture: no access-control modifier at all — out of scope.
contract OpenCounter {
    uint256 public value;

    function set(uint256 next) external {
        value = next;
    }
}
