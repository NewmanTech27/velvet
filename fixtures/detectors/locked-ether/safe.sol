// safe: the contract can receive Ether and has a withdrawal path.
pragma solidity ^0.8.0;

contract TipJar {
    mapping(address => uint256) public tips;

    function tip() external payable {
        tips[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(tips[msg.sender] >= amount, "insufficient");
        tips[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
