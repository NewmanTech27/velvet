// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: library helpers reached through a library call,
/// virtual-dispatch overrides, qualified base calls and constructor-called
/// initializers must not be reported; a genuinely orphaned internal
/// function must be.

library SafeMath2 {
    /// SAFE: called by compute().
    function helper(uint256 x) internal pure returns (uint256) {
        return x * 2;
    }

    /// SAFE: reached through the `using for` library call in run().
    function compute(uint256 x) internal pure returns (uint256) {
        return helper(x) + 1;
    }
}

contract BaseHook {
    /// SAFE: called by callHook(); dispatches to the override below.
    function hook() internal virtual {}

    function callHook() external {
        hook();
    }
}

contract Engine is BaseHook {
    using SafeMath2 for uint256;

    constructor() {
        _init();
    }

    /// SAFE: called from the constructor (runs at deployment).
    function _init() internal {}

    /// SAFE: reached via virtual dispatch from BaseHook.callHook().
    function hook() internal virtual override {}

    modifier onlyPositive(uint256 x) {
        _requirePositive(x);
        _;
    }

    /// SAFE: called from the body of a modifier applied to runChecked().
    function _requirePositive(uint256 x) internal pure {
        require(x > 0, "not positive");
    }

    function run(uint256 x) external pure returns (uint256) {
        return x.compute();
    }

    function runChecked(uint256 x) external pure onlyPositive(x) returns (uint256) {
        return x;
    }

    /// SAFE: reached through the qualified internal call below.
    function qualified(uint256 x) internal pure returns (uint256) {
        return x + 1;
    }

    function runQualified(uint256 x) external pure returns (uint256) {
        return Engine.qualified(x);
    }

    /// VULNERABLE: never called from anywhere.
    function orphan(uint256 x) internal pure returns (uint256) {
        return x + 42;
    }
}
