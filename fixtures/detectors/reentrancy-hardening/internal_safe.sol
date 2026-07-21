// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: checks-effects-interactions *through* an internal
/// helper — the effect is applied in the caller before the helper call.
contract SafeHelperVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function _pay(uint256 amount) internal {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    /// SAFE: the balance is zeroed before the helper performs the call.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        _pay(amount);
    }
}

/// No-Ether variant: flag set before the helper's external call.
contract SafeHelperAuction {
    bool public settled;

    function _notify(address target) internal {
        (bool ok, ) = target.call("");
        require(ok, "notify failed");
    }

    /// SAFE: checks-effects-interactions through the helper.
    function settle(address target) external {
        require(!settled, "already settled");
        settled = true;
        _notify(target);
    }
}
