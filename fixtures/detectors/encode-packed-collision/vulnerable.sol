// vulnerable: abi.encodePacked with two variable-length arguments.
pragma solidity ^0.8.0;

contract MerkleVoting {
    // Two strings are packed without delimiters: ("ab", "c") and ("a", "bc")
    // collide to the same leaf hash.
    function leaf(
        address user,
        string calldata tag,
        string calldata ref
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(tag, ref, user));
    }
}
