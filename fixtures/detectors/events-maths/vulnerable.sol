// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: privileged setters of arithmetic parameters that
/// announce nothing off-chain.
contract Shop {
    address public owner;
    uint256 public priceWei;
    uint256 public feeBps;

    modifier onlyOwner() {
        require(msg.sender == owner, "auth");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setPrice(uint256 p) external onlyOwner {
        priceWei = p; // VULNERABLE: no event for a priced parameter
    }

    function setFee(uint256 f) external onlyOwner {
        _setFee(f); // VULNERABLE: delegated write, still silent
    }

    function _setFee(uint256 f) internal {
        feeBps = f;
    }

    function quote(uint256 amount) external view returns (uint256) {
        uint256 gross = priceWei * amount; // priceWei / feeBps feed arithmetic
        return gross + (gross * feeBps) / 10000;
    }
}
