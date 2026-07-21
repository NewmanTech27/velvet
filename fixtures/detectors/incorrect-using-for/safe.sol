// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: every using-for directive matches at least one
/// library function's first parameter.
library Text {
    function len(string memory s) internal pure returns (uint256) {
        return bytes(s).length;
    }

    function len32(bytes32 b) internal pure returns (uint256) {
        b; // silence unused-parameter style complaints
        return 32;
    }
}

contract SafeData {
    using Text for bytes32; // SAFE: len32(bytes32) matches
    using Text for string; // SAFE: len(string) matches

    bytes32 public blob;
    string public note;
}
