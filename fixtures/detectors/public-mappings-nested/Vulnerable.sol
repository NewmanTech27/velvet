// SPDX-License-Identifier: MIT
// vulnerable: solc < 0.5.0 generates a broken getter for a public mapping
// whose value contains a nested mapping.  velvet's parser requires the
// compact AST of solc >= 0.5, so this fixture documents the pattern for
// the affected compiler; the positive test builds the equivalent core
// model programmatically (as for multiple-constructors).
pragma solidity ^0.4.24;

contract Ledger {
    // broken auto-generated getter pre-0.5.0
    mapping(address => mapping(address => uint256)) public allowances;

    struct Account {
        uint256 nonce;
        mapping(address => uint256) bags;
    }

    // also broken: mapping-to-struct containing a mapping
    mapping(address => Account) public accounts;
}
