// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: declaration-order-dependent initializers.
contract Config {
    uint256 public base = compute(); // VULNERABLE: runs before factor is set
    uint256 public factor = 2;
    uint256 public scaled = compute(); // VULNERABLE: same call, other result
    uint256 public copied = factor; // VULNERABLE: reads a non-constant variable

    function compute() public view returns (uint256) {
        return factor == 0 ? 100 : 100 * factor;
    }
}
