// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: side-effect-free invariants; changes happen outside.
contract SafeCounter {
    uint256 public n;

    function check() external view {
        assert(n > 0); // SAFE: pure condition
        assert(pureSum(1, 2) == 3); // SAFE: pure call inside assert
    }

    function change() external {
        n += 1; // SAFE: state change outside any assert
        require(n > 0, "pos"); // SAFE: require is out of scope for this rule
    }

    function pureSum(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }
}
