// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: ERC-721-named functions with wrong return types.
contract BrokenNFT {
    mapping(uint256 => address) private _owners;

    /// VULNERABLE: ERC-721 requires ownerOf to return address.
    function ownerOf(uint256 tokenId) external view returns (bool) {
        return _owners[tokenId] != address(0);
    }

    /// VULNERABLE: isApprovedForAll must return bool.
    function isApprovedForAll(address owner_, address operator) external pure returns (uint256) {
        return 0;
    }

    /// VULNERABLE: getApproved must return address.
    function getApproved(uint256 tokenId) external view returns (bool) {
        return _owners[tokenId] != address(0);
    }
}
