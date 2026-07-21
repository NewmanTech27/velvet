// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: returndata is discarded or its copied length capped.
contract Reader {
    /// SAFE: the returndata payload is discarded, not copied.
    function fetch(address oracle) external returns (bool) {
        (bool ok, ) = oracle.call(abi.encodeWithSignature("get()"));
        return ok;
    }

    /// SAFE: copied returndata is capped via inline assembly (ExcessivelySafeCall).
    function fetchCapped(address target, bytes memory data)
        external
        returns (bool ok, bytes memory out)
    {
        out = new bytes(32);
        assembly {
            ok := call(gas(), target, 0, add(data, 0x20), mload(data), 0, 0)
            // copy at most 32 bytes of returndata, whatever was returned.
            let n := returndatasize()
            if gt(n, 32) {
                n := 32
            }
            returndatacopy(add(out, 0x20), 0, n)
        }
    }
}
