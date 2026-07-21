// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: a using-for directive bound to a library with no
/// function accepting the attached type.
library Strings {
    function len(string memory s) internal pure returns (uint256) {
        return bytes(s).length;
    }
}

library Counters {
    function incr(uint256 x) internal pure returns (uint256) {
        return x + 1;
    }
}

contract Data {
    using Strings for bytes32; // VULNERABLE: no Strings function takes bytes32
    using Counters for uint256; // fine: incr(uint256) matches

    bytes32 public blob;
    uint256 public total;
}
