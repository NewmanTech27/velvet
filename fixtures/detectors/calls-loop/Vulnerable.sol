// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IShareToken {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// Original fixture: external calls inside loop bodies.
contract Dividends {
    address[] public shareholders;
    IShareToken public bonusToken;

    /// VULNERABLE: one reverting shareholder bricks every payout.
    function distribute() external {
        for (uint256 i = 0; i < shareholders.length; i++) {
            payable(shareholders[i]).transfer(1 ether);
        }
    }

    /// VULNERABLE: high-level token call inside a loop.
    function airdrop(uint256 amount) external {
        uint256 i = 0;
        while (i < shareholders.length) {
            bonusToken.transfer(shareholders[i], amount);
            i++;
        }
    }

    /// VULNERABLE: low-level call inside a loop.
    function notify(bytes calldata data) external {
        for (uint256 i = 0; i < shareholders.length; i++) {
            (bool ok, ) = shareholders[i].call(data);
            require(ok);
        }
    }

    /// VULNERABLE: the loop calls an internal helper that performs the
    /// external call once per iteration.
    function rebate(uint256 amount) external {
        for (uint256 i = 0; i < shareholders.length; i++) {
            _payOne(shareholders[i], amount);
        }
    }

    /// VULNERABLE: external call reached from the loop above.
    function _payOne(address who, uint256 amount) internal {
        bonusToken.transfer(who, amount);
    }

    /// VULNERABLE: the loop calls a virtual hook whose override performs
    /// the external call once per iteration.
    function sweep(uint256 amount) external {
        for (uint256 i = 0; i < shareholders.length; i++) {
            _hook(shareholders[i], amount);
        }
    }

    /// VULNERABLE: external call on a return path inside a loop body — the
    /// node exits the function, which dominator-based natural-loop analysis
    /// cannot attribute to the loop.
    function firstMatch(address target) external returns (bool) {
        for (uint256 i = 0; i < shareholders.length; i++) {
            if (shareholders[i] == target) {
                return bonusToken.transfer(target, 1);
            }
        }
        return false;
    }

    /// VULNERABLE: external call in a do-while body.
    function sweepAll(uint256 amount) external {
        if (shareholders.length == 0) return;
        uint256 i = 0;
        do {
            payable(shareholders[i]).transfer(amount);
            i++;
        } while (i < shareholders.length);
    }

    function _hook(address who, uint256 amount) internal virtual {}

    receive() external payable {}
}

/// Derived implementation: the overridden hook runs the external call.
contract DividendsOverride is Dividends {
    /// VULNERABLE: override reached from Dividends.sweep's loop.
    function _hook(address who, uint256 amount) internal override {
        bonusToken.transfer(who, amount);
    }
}
