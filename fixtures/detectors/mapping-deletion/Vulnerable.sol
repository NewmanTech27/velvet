// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: delete on structs containing a mapping.
contract Profiles {
    struct Profile {
        uint256 joined;
        mapping(address => bool) friends;
    }

    struct Nested {
        Profile inner;
        uint256 tag;
    }

    mapping(address => Profile) public profiles;
    mapping(uint256 => Nested) internal nested;

    /// VULNERABLE: the friends mapping survives the deletion.
    function leave() external {
        delete profiles[msg.sender];
    }

    /// VULNERABLE: transitively contains a mapping through Profile.
    function reset(uint256 id) external {
        delete nested[id];
    }
}
