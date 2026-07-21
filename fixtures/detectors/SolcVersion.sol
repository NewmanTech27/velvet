// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

/// Original fixture: pragma permits outdated solc versions and uses a
/// complex compound constraint (code itself is 0.8-compatible so the
/// highest matching compiler builds it).
contract SolcVersionTarget {
    uint256 public value;

    function set(uint256 next) external {
        value = next;
    }
}
