// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

enum AuctionState {
    Open,
    Closed,
    Settled
}

struct Bid {
    address bidder;
    uint256 amount;
}

/// Contract with events/errors/enums/structs/public getters (original fixture)
/// exercising the interface generator's declaration support.
contract Auction {
    error Unauthorized(address caller);
    error InsufficientBalance(uint256 available, uint256 required);

    AuctionState public state;
    address public beneficiary;
    mapping(address => uint256) public pendingReturns;
    uint256 public highestAmount;

    event BidPlaced(address indexed bidder, uint256 amount);
    event Closed(uint256 finalAmount);

    constructor() {
        beneficiary = msg.sender;
        state = AuctionState.Open;
    }

    function bid(uint256 amount) external {
        uint256 available = pendingReturns[msg.sender];
        if (amount > available) {
            revert InsufficientBalance(available, amount);
        }
        pendingReturns[msg.sender] = available - amount;
        highestAmount = amount;
        emit BidPlaced(msg.sender, amount);
    }

    function placeBid(Bid memory newBid) external {
        emit BidPlaced(newBid.bidder, newBid.amount);
    }

    function close() external returns (AuctionState) {
        if (msg.sender != beneficiary) {
            revert Unauthorized(msg.sender);
        }
        state = AuctionState.Closed;
        emit Closed(highestAmount);
        return state;
    }

    function currentState() external view returns (AuctionState) {
        return state;
    }

    function refund(address who, uint256 amount) external returns (bool) {
        pendingReturns[who] += amount;
        return true;
    }

    function _tally() internal view returns (uint256) {
        return highestAmount;
    }
}
