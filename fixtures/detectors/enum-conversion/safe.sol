// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: the same conversion shape built with a modern
/// compiler, which reverts on out-of-range values (bug window closed).
contract SafeMachine {
    enum State { Off, On }

    function set(uint256 s) external pure returns (State) {
        require(s <= uint256(State.On), "out of range"); // SAFE: explicit check
        return State(uint8(s)); // SAFE: solc >= 0.4.5 range-checks too
    }
}
