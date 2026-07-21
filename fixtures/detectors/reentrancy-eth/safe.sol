// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: checks-effects-interactions and stipend-only sends.
contract SafeVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// SAFE: effect before interaction.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    /// SAFE for reentrancy-eth: send/transfer-only cases are covered by the
    /// fixed-stipend variant, not this detector.
    function withdrawTransfer() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
