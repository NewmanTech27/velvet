pragma solidity ^0.8.0;

// Vulnerable: declarations reuse Solidity built-in symbols.
contract ShadowingBuiltinClock {
    uint256 public now; // shadows the deprecated global `now`

    function stamp() external view returns (uint256) {
        return now; // reads the state variable, not the timestamp
    }

    function legacy(uint256 suicide) external pure returns (uint256) {
        uint256 sha3 = suicide + 1; // shadows the removed builtin `sha3`
        return sha3;
    }
}

// Safe: no declaration collides with a built-in symbol.
contract CleanClock {
    uint256 public timestamp;

    function stamp() external view returns (uint256) {
        return block.timestamp;
    }

    function legacy(uint256 value) external pure returns (uint256) {
        uint256 doubled = value + 1;
        return doubled;
    }
}
