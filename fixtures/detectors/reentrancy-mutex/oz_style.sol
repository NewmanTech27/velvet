// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

error Reentrancy();

/// Original fixture: OpenZeppelin-style unsigned-enum reentrancy guard
/// (require-not-entered / lock / `_` / unlock) applied as a modifier.
/// Every interaction is behind the mutex, so nothing may be flagged.
contract StatusGuardedVault {
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    mapping(address => uint256) public balances;
    uint256 private _status = NOT_ENTERED;

    event Withdrawn(address indexed who, uint256 amount);

    modifier nonReentrant() {
        require(_status != ENTERED, "reentrant call");
        _status = ENTERED;
        _;
        _status = NOT_ENTERED;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// SAFE: the Ether send precedes the balance update in shape, but the
    /// mutex blocks re-entry; the event is emitted while still locked.
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
        emit Withdrawn(msg.sender, amount);
    }

    /// SAFE (no Ether moved): the metering variable is updated after the
    /// call, but the function is mutex-held on every path.
    function notify(address target) external nonReentrant {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = target.call(
            abi.encodeWithSignature("poke(uint256)", amount)
        );
        require(ok, "notify failed");
        balances[msg.sender] = 0;
    }
}

/// Original fixture: the same uint-enum mutex expressed with if-revert
/// (custom error) instead of require.
contract IfRevertGuardedVault {
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    mapping(address => uint256) public balances;
    uint256 private _status = NOT_ENTERED;

    modifier nonReentrant() {
        if (_status == ENTERED) revert Reentrancy();
        _status = ENTERED;
        _;
        _status = NOT_ENTERED;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// SAFE: the if-revert mutex blocks re-entry on every path.
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }
}
