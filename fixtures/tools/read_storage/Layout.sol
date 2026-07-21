// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

struct Pair {
    uint16 a;
    uint16 b;
    uint256 c;
}

/// Storage-layout fixture exercising packing, inheritance, structs,
/// static/dynamic arrays, mappings, enums and bytes/string.
/// Original fixture written for the velvet test suite.
contract LayoutBase {
    uint128 public x;
    uint128 public y;
}

contract Layout is LayoutBase {
    uint256 public u;
    Pair public pair;
    mapping(address => mapping(uint256 => Pair)) public data;
    uint24[] public dyn;
    bytes5[8] public stat;
    string public label;
    bytes public blob;
    bool public flag;
    address public admin;
    int8 public delta;
    uint256 public constant FIXED = 1;
    uint256 public immutable deployed;
    enum Level {
        Low,
        Mid,
        High
    }
    Level public level;

    constructor() {
        deployed = block.number;
    }
}
