// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: re-enterable external calls hosted in modifier bodies.
contract ModifierVault {
    mapping(address => uint256) public balances;

    /// The Ether send lives in the modifier, *before* `_`: it runs before
    /// the function body.
    modifier payOut() {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        _;
    }

    /// VULNERABLE: the call (in payOut) happens before the body zeroes the
    /// balance that metered it.
    function withdraw() external payOut {
        balances[msg.sender] = 0;
    }
}

/// Second pattern: no-Ether call in a modifier, one-shot flag set in body.
contract ModifierAuction {
    bool public settled;

    modifier notifyIfOpen(address target) {
        require(!settled, "already settled");
        (bool ok, ) = target.call("");
        require(ok, "notify failed");
        _;
    }

    /// VULNERABLE: settled is read in the modifier before the call and set
    /// in the body only after it.
    function settle(address target) external notifyIfOpen(target) {
        settled = true;
    }
}
