pragma solidity ^0.8.0;

// Vulnerable: identifiers violate the Solidity style guide.
contract my_token {
    // should be CapWords: MyToken
    uint256 public TOTAL; // non-constant should be mixedCase
    uint256 constant maxSupply = 1; // constant should be MAX_SUPPLY

    event transferred(address to); // events should be CapWords

    struct order {
        uint256 amount; // structs should be CapWords
    }

    enum status { active } // enums should be CapWords

    function TransferCoins(address To) external returns (uint256 RET) {
        uint256 BAD_local = 1; // locals should be mixedCase
        return BAD_local;
    }

    modifier OnlyAdmin() {
        _;
    }
}

// Safe: every identifier follows the style guide.
contract MyToken {
    uint256 public totalSupply;
    uint256 constant MAX_SUPPLY = 1;
    string constant name = "Tok"; // documented ERC-20 exception
    uint256 private _reserved;

    event Transferred(address to);

    struct Order {
        uint256 amount;
    }

    enum Status {
        Active
    }

    function transferCoins(address to) external returns (uint256 amountOut) {
        uint256 baseAmount = 1;
        return baseAmount;
    }

    modifier onlyAdmin() {
        _;
    }

    function touchReserved(uint256 value) external {
        _reserved = value;
    }

    function reserved() external view returns (uint256) {
        return _reserved;
    }
}
