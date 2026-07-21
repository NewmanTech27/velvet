// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Original fixture: call options ({value, gas}), new expressions,
// type conversions, low-level calls.

contract Child {
    constructor() payable {}
}

contract Factory {
    event Created(address instance);

    function spawn() external payable returns (address) {
        Child c = new Child{value: 1 wei}();
        emit Created(address(c));
        return address(c);
    }

    function forward(address payable to) external payable {
        (bool ok, ) = to.call{value: msg.value, gas: 3000}("");
        require(ok, "forward failed");
    }

    function widen(uint64 small) external pure returns (uint256) {
        return uint256(small);
    }
}
