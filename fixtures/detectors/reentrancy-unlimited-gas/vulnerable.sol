// vulnerable: Ether sent via transfer (fixed stipend) before the state update.
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        // checks-effects-interactions violation, limited by the 2300 stipend.
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }
}
