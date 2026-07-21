// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: randomness derived from block variables.
contract CoinFlip {
    /// VULNERABLE: blockhash + timestamp modulo decides the payout.
    function flip() external payable returns (bool win) {
        win = (uint256(blockhash(block.number - 1)) + block.timestamp) % 2 == 0;
        if (win) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }

    /// VULNERABLE: keccak of block properties is still predictable.
    function draw(uint256 tickets) external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.number, msg.sender))) % tickets;
    }

    /// VULNERABLE: plain block.number modulo.
    function pick(uint256 options) external view returns (uint256) {
        return block.number % options;
    }
}
