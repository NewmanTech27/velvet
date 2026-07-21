// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./VaultBase.sol";
import "../base/Owned.sol"; // duplicate import path: flattener must dedupe
import "../base/Counters.sol";

contract TokenVault is VaultBase {
    using Counters for uint256;

    function depositTwice() external payable {
        deposits = deposits.add(msg.value);
        deposits = deposits.add(msg.value);
        emit Deposited(msg.sender, 2 * msg.value);
    }

    function rescue(address to, uint256 amount) external onlyOwner {
        require(amount <= address(this).balance, "insufficient");
        payable(to).transfer(amount);
    }
}
