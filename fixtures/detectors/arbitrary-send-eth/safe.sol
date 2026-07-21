// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: authorized sends and fixed recipients.
contract GuardedFaucet {
    address payable public immutable treasury;
    address public owner;

    constructor(address payable treasury_) {
        require(treasury_ != address(0), "zero treasury");
        treasury = treasury_;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function fund() external payable {}

    /// SAFE: only the owner may choose the destination.
    function drip(address payable to, uint256 amount) external onlyOwner {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "send failed");
    }

    /// SAFE: recipient is a fixed, immutable treasury address.
    function forwardTreasury(uint256 amount) external {
        treasury.transfer(amount);
    }
}
