// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: storage arrays passed to by-value parameters that are
/// modified by the callee — the mutation never reaches the caller's array.
contract Registry {
    uint256[2] public slots;
    uint256[] public entries;

    function init() external {
        bump(slots); // VULNERABLE: bump works on a memory copy
        wipe(slots); // VULNERABLE: the clear is lost as well
    }

    function bump(uint256[2] memory arr) internal pure {
        arr[0] += 1;
    }

    function wipe(uint256[2] memory arr) internal pure {
        arr[1] = 0;
    }

    function initEntries() external {
        entries.push(7);
        touch(entries); // VULNERABLE: dynamic array copied too
    }

    function touch(uint256[] memory arr) internal pure {
        arr[0] = 99;
    }
}
