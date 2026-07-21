// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: the same nested public mappings compile on a modern
/// compiler whose generated getters are correct.
contract Ledger {
    /// SAFE: solc >= 0.5.0 generates a correct nested getter.
    mapping(address => mapping(address => uint256)) public allowances;

    struct Account {
        uint256 nonce;
        mapping(address => uint256) bags;
    }

    /// SAFE: mapping-to-struct is fine on modern compilers.
    mapping(address => Account) public accounts;

    /// SAFE: private nested mappings have no generated getter at all.
    mapping(address => mapping(address => uint256)) private hidden;
}
