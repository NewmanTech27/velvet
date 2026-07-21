// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: deletions that clear everything they touch.
contract SafeProfiles {
    struct Profile {
        uint256 joined;
        bool active;
    }

    mapping(address => Profile) public profiles;
    mapping(address => uint256) public scores;
    mapping(address => bool) public friends;

    /// SAFE: the struct holds no mapping — delete clears it fully.
    function leave() external {
        delete profiles[msg.sender];
    }

    /// SAFE: deleting a plain value-type mapping entry.
    function resetScore() external {
        delete scores[msg.sender];
    }

    /// SAFE: deleting the mapping entry directly, not a wrapper struct.
    function unfriend(address other) external {
        delete friends[other];
    }
}
