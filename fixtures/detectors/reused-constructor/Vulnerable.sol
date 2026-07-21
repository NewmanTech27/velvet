// SPDX-License-Identifier: MIT
// vulnerable: A's constructor is invoked with arguments from two distinct
// sites reachable from D (B passes 10, C passes 20); only one invocation
// executes and the other is silently ignored.  solc >= 0.5 rejects the
// pattern ("Base constructor arguments given twice"), so this fixture
// documents it for old compilers; the positive test builds the
// equivalent core model programmatically.
pragma solidity ^0.4.24;

contract A {
    uint256 public fee;
    constructor(uint256 f) public { fee = f; }
}

contract B is A {
    constructor() A(10) public {}
}

contract C is A {
    constructor() A(20) public {}
}

contract D is B, C {
    constructor() public {} // A built with fee 10 (B's call); C's A(20) ignored
}
