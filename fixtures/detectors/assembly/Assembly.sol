pragma solidity ^0.8.0;

// Vulnerable (review aid): inline assembly usage.
contract AssemblyUser {
    function double(uint256 x) external pure returns (uint256 y) {
        assembly {
            y := add(x, x) // flagged for manual review
        }
    }
}

// Safe: pure Solidity only.
contract NoAssembly {
    function double(uint256 x) external pure returns (uint256) {
        return x + x;
    }
}
