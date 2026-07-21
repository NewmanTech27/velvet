// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "./Initializable.sol";

/// @notice A broken upgradeable implementation: the initializer is not
/// guarded by the `initializer` modifier (re-initializable), a state
/// variable is initialized at declaration time (invisible through the
/// proxy), and a selfdestruct path can brick every attached proxy.
contract BrokenImpl is Initializable {
    address public owner;
    uint256 public threshold = 5;

    function initialize() external {
        owner = msg.sender;
    }

    function setThreshold(uint256 newThreshold) external {
        require(msg.sender == owner, "not owner");
        threshold = newThreshold;
    }

    function kill() external {
        require(msg.sender == owner, "not owner");
        selfdestruct(payable(owner));
    }
}
