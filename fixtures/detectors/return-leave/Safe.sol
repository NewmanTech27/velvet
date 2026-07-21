// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: assembly blocks that leave the Solidity return path
/// intact.
contract SafeCodec {
    /// SAFE: the assembly block stores the named return and simply ends,
    /// so the compiler-generated epilogue encodes `a` as usual.
    function encode(uint256 x) external pure returns (bytes32 a) {
        assembly {
            mstore(0, x)
            a := mload(0)
        }
    }

    /// SAFE: leave correctly exits the Yul helper function only; the
    /// Solidity epilogue still runs.
    function encodeTwice(uint256 x) external pure returns (bytes32 a) {
        assembly {
            function dbl(v) -> r {
                r := add(v, v)
                leave
            }
            a := dbl(x)
        }
    }
}

/// SAFE: bare forwarder — no declared returns and no logic after the
/// assembly block, so return() is the intended frame terminator.
contract Forwarder {
    fallback() external {
        assembly {
            let size := calldatasize()
            calldatacopy(0, 0, size)
            return(0, size)
        }
    }
}
