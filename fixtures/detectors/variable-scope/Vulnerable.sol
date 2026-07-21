// SPDX-License-Identifier: MIT
// vulnerable: pre-0.5.0 scoping rules accept uses before the declaration
// is executed (function-wide scope); the use observes the zero value.
// velvet's parser requires the compact AST of solc >= 0.5, so this
// fixture documents the pattern for the affected compiler; the positive
// test builds the equivalent core model programmatically.
pragma solidity ^0.4.24;

contract Scope {
    function f(bool cond) public pure returns (uint256) {
        uint256 result = bonus + 1; // used before declaration: bonus is 0
        uint256 bonus = 5;
        if (cond) {
            uint256 limit = 10;
        }
        return result + limit; // limit only initialized in the if-scope
    }
}
