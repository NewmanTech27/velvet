// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: classic Ether-theft reentrancy patterns.
contract EtherVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// VULNERABLE: Ether sent before the balance is zeroed.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }

    /// VULNERABLE: the metering state var is read inside the call itself.
    function withdrawAll() external {
        (bool ok, ) = msg.sender.call{value: balances[msg.sender}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }
}

/// Second contract in the same unit: also vulnerable (per-contract iteration).
contract PrizePool {
    mapping(address => uint256) public tickets;

    function buyTicket() external payable {
        tickets[msg.sender] += msg.value;
    }

    /// VULNERABLE: state var read before, zeroed after the Ether send.
    function claimPrize() external {
        uint256 prize = tickets[msg.sender];
        (bool ok, ) = msg.sender.call{value: prize}("");
        require(ok);
        tickets[msg.sender] = 0;
    }
}
