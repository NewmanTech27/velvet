pragma solidity ^0.8.0;

// Vulnerable: `legacySupply` is never used and `admin` is written in the
// constructor but never read anywhere.
contract UnusedStateToken {
    string public name = "Tok";
    uint256 private legacySupply; // assigned nowhere, read nowhere
    address private admin; // written in constructor but never read

    constructor() {
        admin = msg.sender;
    }
}

// Safe: every non-public variable is read by some function (directly or
// through an internal helper), public variables have implicit getters.
contract UsedStateToken {
    string public name = "Tok";
    uint256 private total;
    address private admin;

    constructor() {
        admin = msg.sender;
    }

    function add(uint256 amount) external {
        total += amount;
    }

    function currentTotal() external view returns (uint256) {
        return _readTotal();
    }

    function _readTotal() internal view returns (uint256) {
        return total;
    }

    function adminOf() external view returns (address) {
        return admin;
    }
}
