// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// SAFE fixture: every internal routine is reachable from an entry point.
contract SafeEngine {
    uint256 private _total;

    function run(uint256 x) external pure returns (uint256) {
        return _bump(x);
    }

    /// SAFE: called by the external run().
    function _bump(uint256 x) internal pure returns (uint256) {
        return _double(x) + 1;
    }

    /// SAFE: called transitively through _bump().
    function _double(uint256 x) private pure returns (uint256) {
        return x * 2;
    }

    /// SAFE: public/external functions are entry points, never dead code.
    function unusedExternal(uint256 x) external pure returns (uint256) {
        return x + 42;
    }
}
