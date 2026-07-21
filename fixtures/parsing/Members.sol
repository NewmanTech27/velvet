// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Original fixture: declaration surface (top-level items, struct, enum,
// error, event, using-for, library) for declaration-parsing tests.

uint256 constant MAX_SUPPLY = 1000;

function doubleIt(uint256 x) pure returns (uint256) {
    return x * 2;
}

struct Order {
    address maker;
    uint256 amount;
}

enum Status {
    Open,
    Filled,
    Cancelled
}

error OrderTooLarge(uint256 amount, uint256 maximum);

library OrderBook {
    function validate(Order memory o) internal pure {
        if (o.amount > MAX_SUPPLY) {
            revert OrderTooLarge(o.amount, MAX_SUPPLY);
        }
    }
}

contract Exchange {
    using OrderBook for Order;

    event OrderPlaced(address indexed maker, uint256 amount, Status status);

    Status public status;
    Order[] public orders;

    function place(uint256 amount) external {
        Order memory o = Order(msg.sender, amount);
        o.validate();
        orders.push(o);
        status = Status.Filled;
        emit OrderPlaced(msg.sender, amount, Status.Filled);
    }
}
