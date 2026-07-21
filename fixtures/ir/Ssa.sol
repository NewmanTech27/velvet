// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture exercising SSA construction (architecture.md §6.5):
/// versioning, merge phis, entry/external-call phis for state variables,
/// and storage-alias phis.
contract Ssa {
    uint256 public total;
    uint256[] public left;
    uint256[] public right;
    mapping(address => uint256) public balances;

    function branch(uint256 amount) external {
        uint256 fee = 0;
        if (amount > 100) {
            fee = amount / 10;
        } else {
            fee = 1;
        }
        total = total + amount - fee; // fee needs a merge phi
    }

    function callOut(address payable to, uint256 amount) external {
        to.transfer(amount); // external call: total may change via reentrancy
        total = total - amount;
    }

    function aliasWrite(bool which, uint256 x) external {
        uint256[] storage ref = left;
        if (which) {
            ref = right; // ref may alias {left, right}
        }
        ref.push(x); // write through alias -> phis for left and right
    }

    function loop(uint256 n) external returns (uint256) {
        uint256 s = 0;
        for (uint256 i = 0; i < n; i++) {
            s += i; // loop-carried phis at IF_LOOP
        }
        return s;
    }
}
