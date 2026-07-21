// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: returndata copied wholesale into memory.
contract Reader {
    /// VULNERABLE: whatever `oracle` returns is copied into memory.
    function fetch(address oracle) external returns (bool) {
        (bool ok, bytes memory payload) = oracle.call(abi.encodeWithSignature("get()"));
        return ok && payload.length >= 0;
    }

    /// VULNERABLE: returndata of a delegatecall is copied into memory.
    function run(address impl, bytes calldata data) external returns (bool) {
        (bool ok, bytes memory result) = impl.delegatecall(data);
        return ok && result.length >= 0;
    }
}
