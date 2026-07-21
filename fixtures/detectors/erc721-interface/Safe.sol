// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: conforming ERC-721 surface and harmless overloads.
contract ConformingNFT {
    mapping(uint256 => address) private _owners;

    /// SAFE: exactly ownerOf(uint256) returns (address).
    function ownerOf(uint256 tokenId) external view returns (address) {
        return _owners[tokenId];
    }

    /// SAFE: transferFrom returns nothing, as specified.
    function transferFrom(address from, address to, uint256 tokenId) external {}

    /// SAFE: safeTransferFrom (with data) returns nothing, as specified.
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external {}

    /// SAFE: isApprovedForAll returns bool.
    function isApprovedForAll(address owner_, address operator) external pure returns (bool) {
        return false;
    }
}

/// SAFE: an ownerOf overload with different parameters is not an ERC-721
/// collision.
contract Registry {
    function ownerOf(uint256 tokenId, string calldata label) external pure returns (bool) {
        return true;
    }
}

/// SAFE: a full ERC-20 token — its transferFrom/approve signatures are the
/// ERC-20 standard, not broken ERC-721 methods (checked by erc20-interface).
contract StandardToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    function transfer(address to, uint256 amount) external returns (bool) {
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        return true;
    }
}
