// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// ERC-20 token with deliberate deviations (original fixture):
///  1. transfer does not return bool
///  2. balanceOf is not view
///  3. allowance is missing entirely
///  4. approve does not emit Approval
///  5. Transfer's second parameter is not indexed
///  6. optional name/symbol/decimals are missing (warnings only)
contract BadToken {
    uint256 public totalSupply;

    mapping(address => uint256) internal _balances;
    mapping(address => mapping(address => uint256)) internal _allowances;

    event Transfer(address indexed from, address to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 initialSupply) {
        totalSupply = initialSupply;
        _balances[msg.sender] = initialSupply;
    }

    function balanceOf(address owner) external returns (uint256) {
        return _balances[owner];
    }

    function transfer(address to, uint256 amount) external {
        _move(msg.sender, to, amount);
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        uint256 allowed = _allowances[from][msg.sender];
        require(allowed >= amount, "allowance too low");
        _allowances[from][msg.sender] = allowed - amount;
        _move(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        _allowances[msg.sender][spender] = amount;
        return true;
    }

    function _move(address from, address to, uint256 amount) internal {
        require(_balances[from] >= amount, "balance too low");
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
    }
}
