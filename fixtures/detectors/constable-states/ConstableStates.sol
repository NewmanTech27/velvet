pragma solidity ^0.8.0;

// Vulnerable: variables assigned once at declaration and never modified
// afterwards should be declared constant.
contract ConstableFees {
    uint256 public maxFeeBps = 500; // never changed -> should be constant
    string public version = "1.0"; // never changed -> should be constant
    uint256 public changeable = 1; // written below -> fine
    uint256 constant ALREADY_CONSTANT = 2; // already constant -> fine

    function setChangeable(uint256 value) external {
        changeable = value;
    }
}

// Safe: every non-constant variable is written after declaration.
contract MutableFees {
    uint256 public feeBps;
    uint256 constant FEE_CAP = 10_000;

    function setFee(uint256 value) external {
        feeBps = value;
    }
}
