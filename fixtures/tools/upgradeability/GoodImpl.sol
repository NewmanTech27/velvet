// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "./Initializable.sol";

/// @notice Upgradeable ownable base following the storage-gap convention:
/// the gap reserves 50 - (own variables) slots for future versions.
abstract contract OwnableUpgradeable is Initializable {
    address public owner;

    // 1 variable declared -> 49 slots reserved.
    uint256[49] private __gap;

    modifier onlyOwner() {
        require(msg.sender == owner, "Ownable: not owner");
        _;
    }

    function initializeOwner() internal {
        owner = msg.sender;
    }
}

/// @notice A model upgradeable implementation: protected initializer,
/// chained base initializers, no declaration-time initialization,
/// gaps in place, no selfdestruct / delegatecall.
contract GoodImpl is OwnableUpgradeable {
    uint256 public value;

    // 1 own variable -> 49 slots reserved.
    uint256[49] private __gap;

    constructor() {
        _disableInitializers();
    }

    function initialize() external initializer {
        initializeOwner();
        value = 42;
    }

    function setValue(uint256 newValue) external onlyOwner {
        value = newValue;
    }
}
