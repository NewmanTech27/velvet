// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: assembly return inside an internally-called helper.
contract SizeReader {
    function _size(address a) internal view returns (uint256 s) {
        assembly {
            s := extcodesize(a)
            return(0, 32) // VULNERABLE: halts the whole call frame
        }
    }

    function check(address a) external view returns (bool) {
        uint256 s = _size(a);
        return s > 0; // never reached
    }
}
