// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: an honestly-declared view function (reads only) built
/// with a modern compiler, where the attributes are enforced.
contract SafeStats {
    uint256 public queries;

    function total() external view returns (uint256) {
        return queries; // SAFE: no state change, and compiler >= 0.5
    }

    function record() external {
        queries += 1; // SAFE: not declared constant/view/pure
    }
}
