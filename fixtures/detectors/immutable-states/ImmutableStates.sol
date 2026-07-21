pragma solidity ^0.8.0;

// Vulnerable: variables assigned only in the constructor (or with a
// non-constant declaration initializer) should be declared immutable.
contract ImmutableVault {
    address public owner; // set once in constructor -> should be immutable
    uint256 public created; // set once in constructor -> should be immutable
    uint256 public deployedAt = block.timestamp; // non-constant init -> immutable
    uint256 public maxFeeBps = 500; // constant-able -> not immutable
    uint256 public changed; // written outside the constructor -> fine
    address public immutable preset; // already immutable -> fine

    constructor() {
        owner = msg.sender;
        created = block.timestamp;
        preset = msg.sender;
    }

    function setChanged(uint256 value) external {
        changed = value;
    }
}

// Safe: nothing to upgrade — variables are immutable, constant, or mutated
// after construction.
contract MutableVault {
    address public immutable owner;
    uint256 public counter;
    uint256 constant CAP = 10;

    constructor() {
        owner = msg.sender;
    }

    function bump() external {
        counter += 1;
    }
}
