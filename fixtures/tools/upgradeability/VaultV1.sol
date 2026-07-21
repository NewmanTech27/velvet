// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "./Initializable.sol";

/// @notice V1 of an upgradeable vault — the storage-layout baseline.
contract VaultV1 is Initializable {
    address public owner;
    uint256 public totalDeposits;
    mapping(address => uint256) public deposits;
    uint256 public constant VERSION = 1;

    // 3 variables declared -> 47 slots reserved.
    uint256[47] private __gap;

    function initialize(address newOwner) external initializer {
        owner = newOwner;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
}
