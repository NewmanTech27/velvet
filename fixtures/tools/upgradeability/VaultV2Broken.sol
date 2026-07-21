// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "./Initializable.sol";

/// @notice Incompatible V2: `owner` and `totalDeposits` swapped places.
contract VaultV2Reorder is Initializable {
    uint256 public totalDeposits;
    address public owner;
    mapping(address => uint256) public deposits;
    uint256 public constant VERSION = 1;

    uint256[47] private __gap;

    function initialize(address newOwner) external initializer {
        owner = newOwner;
    }
}

/// @notice Incompatible V2: `withdrawalFee` inserted in the middle,
/// shifting every later variable by one slot.
contract VaultV2Insert is Initializable {
    address public owner;
    uint256 public withdrawalFee;
    uint256 public totalDeposits;
    mapping(address => uint256) public deposits;
    uint256 public constant VERSION = 1;

    uint256[47] private __gap;

    function initialize(address newOwner) external initializer {
        owner = newOwner;
    }
}

/// @notice Incompatible V2: `totalDeposits` deleted — a later V3
/// re-adding a variable at that position would read stale values.
contract VaultV2Delete is Initializable {
    address public owner;
    mapping(address => uint256) public deposits;
    uint256 public constant VERSION = 1;

    uint256[47] private __gap;

    function initialize(address newOwner) external initializer {
        owner = newOwner;
    }
}

/// @notice Incompatible V2: `totalDeposits` retyped uint256 -> uint128.
contract VaultV2Retype is Initializable {
    address public owner;
    uint128 public totalDeposits;
    mapping(address => uint256) public deposits;
    uint256 public constant VERSION = 1;

    uint256[47] private __gap;

    function initialize(address newOwner) external initializer {
        owner = newOwner;
    }
}

/// @notice Incompatible V2: `totalDeposits` became constant — removes a
/// storage slot and shifts the layout of every later variable.
contract VaultV2Const is Initializable {
    address public owner;
    uint256 public constant totalDeposits = 0;
    mapping(address => uint256) public deposits;
    uint256 public constant VERSION = 1;

    uint256[47] private __gap;

    function initialize(address newOwner) external initializer {
        owner = newOwner;
    }
}

/// @notice Incompatible V2: `VERSION` was constant in V1 and became a
/// normal state variable — inserts a storage slot and shifts the layout.
contract VaultV2Unconst is Initializable {
    address public owner;
    uint256 public totalDeposits;
    mapping(address => uint256) public deposits;
    uint256 public VERSION;

    uint256[47] private __gap;

    function initialize(address newOwner) external initializer {
        owner = newOwner;
        VERSION = 2;
    }
}

/// @notice Gap-hygiene violation: appends a variable but keeps the gap
/// at 47 slots instead of shrinking it to 46.
contract VaultV2BadGap is Initializable {
    address public owner;
    uint256 public totalDeposits;
    mapping(address => uint256) public deposits;
    uint256 public constant VERSION = 1;
    uint256 public withdrawalFee;

    uint256[47] private __gap;

    function initialize(address newOwner) external initializer {
        owner = newOwner;
    }
}

/// @notice Layout-compatible but introduces a selfdestruct path — the
/// upgrade becomes upgradeable-incompatible.
contract VaultV2Destructive is Initializable {
    address public owner;
    uint256 public totalDeposits;
    mapping(address => uint256) public deposits;
    uint256 public constant VERSION = 1;

    uint256[47] private __gap;

    function initialize(address newOwner) external initializer {
        owner = newOwner;
    }

    function kill() external {
        require(msg.sender == owner, "not owner");
        selfdestruct(payable(owner));
    }
}
