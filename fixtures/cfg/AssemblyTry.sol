// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Original fixture: opaque assembly node, try/catch, emit, revert,
// named returns with synthesized trailing RETURN.

interface IOracle {
    function get() external returns (uint256);
}

contract AssemblyTry {
    event Fetched(address indexed source, uint256 value);

    error CallFailed(address source);

    address public oracle;

    constructor(address o) {
        oracle = o;
    }

    function fetch() external returns (uint256 value) {
        try IOracle(oracle).get() returns (uint256 result) {
            value = result;
            emit Fetched(oracle, result);
        } catch {
            revert CallFailed(oracle);
        }
    }

    function manualAdd(uint256 a, uint256 b) external pure returns (uint256 result) {
        assembly {
            result := add(a, b)
        }
    }
}
