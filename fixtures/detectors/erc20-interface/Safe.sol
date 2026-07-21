// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: conforming ERC-20 surface and harmless name reuse.
contract ConformingToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    /// SAFE: exactly the ERC-20 signature and return type.
    function transfer(address to, uint256 amount) external returns (bool) {
        return true;
    }

    /// SAFE: transferFrom returns bool.
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        return true;
    }

    /// SAFE: approve returns bool.
    function approve(address spender, uint256 amount) external returns (bool) {
        return true;
    }
}

/// SAFE: a function merely *named* transfer with different parameters is
/// not an ERC-20 collision.
contract Relayer {
    function transfer(address target) external {}
}

/// SAFE: an ERC-721 collection — its transferFrom/approve return nothing
/// per the ERC-721 standard (checked by erc721-interface, not this rule).
contract NFTCollection {
    mapping(uint256 => address) private _owners;

    function ownerOf(uint256 tokenId) external view returns (address) {
        return _owners[tokenId];
    }

    function balanceOf(address owner_) external pure returns (uint256) {
        return 0;
    }

    function transferFrom(address from, address to, uint256 tokenId) external {}

    function approve(address approved, uint256 tokenId) external {}

    function safeTransferFrom(address from, address to, uint256 tokenId) external {}
}
