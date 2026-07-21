// safe: every read state variable is assigned somewhere.
pragma solidity ^0.8.0;

contract Fundraiser {
    address payable public beneficiary;

    // written at declaration.
    uint256 public cap = 100 ether;

    // written only, never read: unused-state, not uninitialized-state.
    uint256 private lastAmount;

    constructor() {
        beneficiary = payable(msg.sender);
    }

    function donate() external payable {
        lastAmount = msg.value;
        beneficiary.transfer(msg.value);
    }
}
