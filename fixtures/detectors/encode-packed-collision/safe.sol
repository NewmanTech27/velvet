// safe: at most one variable-length argument, or abi.encode instead.
pragma solidity ^0.8.0;

contract MerkleVoting {
    // One variable-length argument only: no ambiguity.
    function leaf(address user, string calldata tag) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(tag, user));
    }

    // abi.encode length-prefixes dynamic arguments.
    function leafSafe(
        string calldata tag,
        string calldata ref
    ) external pure returns (bytes32) {
        return keccak256(abi.encode(tag, ref));
    }
}
