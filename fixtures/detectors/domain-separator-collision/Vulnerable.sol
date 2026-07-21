// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: DOMAIN_SEPARATOR colliding declarations in permit tokens.
contract BadOverloadToken {
    mapping(address => uint256) public balanceOf;

    /// VULNERABLE: overloaded DOMAIN_SEPARATOR with a different signature.
    function DOMAIN_SEPARATOR(bytes32 extra) external pure returns (bytes32) {
        return extra;
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

contract BadReturnToken {
    mapping(address => uint256) public balanceOf;

    /// VULNERABLE: right arity but the return type is not bytes32.
    function DOMAIN_SEPARATOR() external pure returns (uint256) {
        return 1;
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
