// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture exercising one IR op per shape (architecture.md §6.3).
library Counter {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}

contract Ops {
    using Counter for uint256;

    struct Order {
        address maker;
        uint256 amount;
    }

    uint256 public total;
    uint256[] public values;
    mapping(address => uint256) public balances;
    Order[] public orders;

    event Deposited(address indexed who, uint256 amount);

    constructor() payable {}

    receive() external payable {}

    function _double(uint256 v) internal pure returns (uint256) {
        return v * 2;
    }

    function arithmetic(uint256 a, uint256 b) external returns (uint256) {
        uint256 c = a + b; // Binary
        c += 1; // compound: Binary + Assignment
        c++; // inc: read-back + Binary + Assignment
        bool neg = c == 0; // Binary ==
        uint256 d = _double(c); // InternalCall
        return neg ? 0 : d; // parser-lowered ternary
    }

    function arrays(uint256 x) external {
        values.push(x); // Push
        values[0] = x; // Index + Assignment
        total = values[1]; // Index read
        delete values[0]; // Delete
        uint256[] memory fresh = new uint256[](3); // NewArray
        fresh[0] = x;
    }

    function structsAndMaps(address who, uint256 amount) external {
        balances[who] += amount; // REF write
        Order memory o = Order(who, amount); // NewStructure
        orders.push(o);
        total = orders[0].amount; // Index + Member chain
    }

    function libraryUse(uint256 x) external returns (uint256) {
        return x.add(2); // LibraryCall via using-for, receiver first arg
    }

    function emitAndRequire(uint256 amount) external {
        require(amount > 0, "amount"); // SolidityCall require
        emit Deposited(msg.sender, amount); // EventCall
    }

    function money(address payable to, uint256 amount) external {
        to.transfer(amount); // Transfer
        bool ok = to.send(1); // Send
        (bool called, ) = to.call{value: 1, gas: 5000}(""); // LowLevelCall + Unpack
        require(ok && called, "failed");
    }

    function typeplay(address who) external {
        uint160 bits = uint160(who); // TypeConversion
        total = uint256(bits);
    }
}

contract Factory {
    Ops public deployed;

    function build() external returns (Ops) {
        deployed = new Ops{value: 1}(); // NewContract
        return deployed;
    }

    function useIt(uint256 a, uint256 b) external returns (uint256) {
        return deployed.arithmetic(a, b); // HighLevelCall
    }
}
