// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: re-enterable external calls inside internal helpers,
/// with the effect (state write) in the caller after the helper call.
contract HelperVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function _pay(uint256 amount) internal {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    /// VULNERABLE: the external call inside _pay runs before the caller
    /// zeroes the balance that metered it.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        _pay(amount);
        balances[msg.sender] = 0;
    }
}

/// No-Ether variant: external call in the helper, one-shot flag in caller.
contract HelperAuction {
    bool public settled;

    function _notify(address target) internal {
        (bool ok, ) = target.call("");
        require(ok, "notify failed");
    }

    /// VULNERABLE: settled is read before the helper call and set after it.
    function settle(address target) external {
        require(!settled, "already settled");
        _notify(target);
        settled = true;
    }
}

/// A directly recursive internal helper: the recursion must be detected and
/// skipped (intra-procedural fallback) rather than looping forever; the
/// pattern visible in the body itself is still reported.
contract RecursiveVault {
    mapping(address => uint256) public balances;

    function _spin(uint256 amount, uint256 rounds) internal {
        if (rounds == 0) {
            return;
        }
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        _spin(amount, rounds - 1);
    }

    /// VULNERABLE: the call in _spin runs before the caller zeroes the
    /// balance.
    function withdraw(uint256 rounds) external {
        uint256 amount = balances[msg.sender];
        _spin(amount, rounds);
        balances[msg.sender] = 0;
    }
}
