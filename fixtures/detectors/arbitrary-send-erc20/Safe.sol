// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// SAFE fixture: transferFrom is constrained to msg.sender.
contract TokenVault {
    mapping(address => uint256) public deposited;

    /// SAFE: from is always the caller.
    function deposit(IERC20 token, uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        deposited[msg.sender] += amount;
    }

    /// SAFE: from is a local alias of msg.sender.
    function depositAlias(IERC20 token, uint256 amount) external {
        address payer = msg.sender;
        token.transferFrom(payer, address(this), amount);
        deposited[payer] += amount;
    }
}

contract BaseToken {
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public virtual returns (bool) {
        return true;
    }
}

/// SAFE (FP regression): the enclosing function is itself the transferFrom
/// implementation forwarding to super; `from` is its own parameter,
/// governed by the enclosing allowance semantics (CMTAT mock-upgrade FP).
contract UpgradeableToken is BaseToken {
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public virtual override returns (bool) {
        return super.transferFrom(from, to, amount);
    }
}

/// SAFE (FP regression): a dominating require ties `from` to the caller,
/// so the spender is explicitly authorized before the pull.
contract AllowanceChecked {
    function pull(IERC20 token, address from, uint256 amount) external {
        require(from == msg.sender, "not authorized");
        token.transferFrom(from, address(this), amount);
    }
}
