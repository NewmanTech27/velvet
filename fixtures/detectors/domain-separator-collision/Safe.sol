// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: conforming DOMAIN_SEPARATOR, and overloads outside
/// permit tokens (out of scope).
contract GoodToken {
    mapping(address => uint256) public balanceOf;
    bytes32 private immutable _separator;

    constructor() {
        _separator = block.chainid == 1 ? bytes32(uint256(1)) : bytes32(uint256(2));
    }

    /// SAFE: exactly DOMAIN_SEPARATOR() returns (bytes32).
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _separator;
    }

    function permit(
        address owner_,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {}
}

/// SAFE: no permit support, so the overload collides with nothing.
contract NotAPermitToken {
    function DOMAIN_SEPARATOR(bytes32 extra) external pure returns (bytes32) {
        return extra;
    }
}
