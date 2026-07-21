// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MathLib} from "minilib/MathLib.sol";

/// @notice Tiny counter exercising a lib/ dependency through a remapping.
contract Counter {
    uint256 public count;

    function increment() external {
        count = MathLib.add(count, 1);
    }
}
