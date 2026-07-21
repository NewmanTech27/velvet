// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: announced changes, non-arithmetic state, and
/// unprivileged setters — all out of scope.
contract SafeShop {
    address public owner;
    uint256 public priceWei;
    uint256 public tag;
    uint256 public open;

    event PriceUpdated(uint256 previous, uint256 next);

    modifier onlyOwner() {
        require(msg.sender == owner, "auth");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setPrice(uint256 p) external onlyOwner {
        emit PriceUpdated(priceWei, p); // SAFE: change is announced
        priceWei = p;
    }

    function setTag(uint256 t) external onlyOwner {
        tag = t; // SAFE: tag feeds no arithmetic anywhere
    }

    function setOpen(uint256 o) external {
        open = o; // SAFE: no access-control modifier
    }

    function quote(uint256 amount) external view returns (uint256) {
        return priceWei * amount + open;
    }
}
