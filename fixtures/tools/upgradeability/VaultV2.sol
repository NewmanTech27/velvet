// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "./Initializable.sol";

/// @notice V2 of the vault — a *compatible* upgrade: the only storage
/// change is `withdrawalFee` appended after all V1 variables, and the
/// storage gap is shrunk by the same number of slots.
contract VaultV2 is Initializable {
    address public owner;
    uint256 public totalDeposits;
    mapping(address => uint256) public deposits;
    uint256 public constant VERSION = 1;
    uint256 public withdrawalFee;

    // 4 variables declared -> 46 slots reserved.
    uint256[46] private __gap;

    function initialize(address newOwner) external initializer {
        owner = newOwner;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function setWithdrawalFee(uint256 fee) external {
        require(msg.sender == owner, "not owner");
        withdrawalFee = fee;
    }
}
