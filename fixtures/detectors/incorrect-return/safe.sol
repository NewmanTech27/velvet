// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: a helper that returns normally, and an outermost
/// assembly return that is never invoked internally.
contract SafeSizeReader {
    function _size(address a) internal view returns (uint256 s) {
        assembly {
            s := extcodesize(a) // SAFE: returns to the caller normally
        }
    }

    function check(address a) external view returns (bool) {
        return _size(a) > 0;
    }

    function raw() external pure {
        assembly {
            return(0, 32) // SAFE: outermost context, no internal callers
        }
    }
}
