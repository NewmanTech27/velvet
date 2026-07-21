// safe: a single modern constructor; no function is named like the contract.
pragma solidity ^0.8.0;

contract Token {
    uint256 public supply;

    constructor() {
        supply = 1000;
    }

    function mint(uint256 amount) external {
        supply += amount;
    }
}
