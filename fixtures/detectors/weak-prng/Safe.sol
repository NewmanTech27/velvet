// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// SAFE fixture: randomness comes from a verifiable oracle / commit-reveal,
/// never from block variables.
contract SafeLottery {
    uint256 private _vrfWord;
    uint256 private _nonce;

    /// The VRF coordinator fulfills randomness here.
    function fulfillRandomness(uint256 randomWord) external {
        _vrfWord = randomWord;
    }

    /// SAFE: entropy comes from the oracle-provided word.
    function draw(uint256 tickets) external returns (uint256) {
        _nonce += 1;
        return uint256(keccak256(abi.encodePacked(_vrfWord, _nonce))) % tickets;
    }

    /// SAFE: commit-reveal; the modulo only mixes user secrets.
    function reveal(bytes32 salt, uint256 secret, uint256 tickets) external pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(salt, secret))) % tickets;
    }
}
