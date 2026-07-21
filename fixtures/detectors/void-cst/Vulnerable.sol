// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Base with no explicit constructor.
contract Base {
    uint256 internal value;
}

/// VULNERABLE: Base() executes nothing but suggests initialization.
contract Child is Base {
    constructor() Base() {
        value = 1;
    }
}
