// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: every base constructor with parameters is invoked
/// with arguments from exactly one site per derived contract.
contract A {
    uint256 public fee;

    constructor(uint256 f) {
        fee = f;
    }
}

/// SAFE: B is the single site calling A(uint256) with arguments.
contract B is A {
    constructor() A(10) {}
}

/// SAFE: D adds no second argument-passing call to A's constructor.
contract D is B {
    constructor() {}
}

/// SAFE: the pass-through is still a single site with arguments.
contract E is A {
    constructor(uint256 f) A(f) {}
}
