// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ERC-7201 namespaced-storage accessor: a contract-level CONSTANT is read
// inside inline assembly (`$.slot := SLOT`). The Yul model must resolve the
// identifier to the constant -- not mint a synthetic local that shadows the
// state variable (shadowing-local FP) or reads "uninitialized"
// (uninitialized-local FP).
contract ERC7201Like {
    bytes32 private constant SLOT =
        0x02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800;

    struct Layout {
        uint256 total;
    }

    function _layout() private pure returns (Layout storage $) {
        assembly {
            $.slot := SLOT
        }
    }

    function set(uint256 v) external {
        Layout storage $ = _layout();
        $.total = v;
    }
}
