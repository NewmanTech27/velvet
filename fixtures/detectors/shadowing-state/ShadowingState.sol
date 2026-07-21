pragma solidity 0.5.8;

// Vulnerable: Vault re-declares `owner`, shadowing Owned.owner. The
// onlyOwner modifier keeps reading the unset base slot.
contract Owned {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "auth");
        _;
    }
}

contract ShadowedVault is Owned {
    address public owner; // shadows Owned.owner

    constructor() public {
        owner = msg.sender;
    }

    function close() external onlyOwner {}
}

// Safe: the derived contract assigns the inherited variable through the
// base constructor instead of re-declaring it.
contract OwnedSafe {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "auth");
        _;
    }
}

contract CleanVault is OwnedSafe {
    function close() external onlyOwner {}
}
