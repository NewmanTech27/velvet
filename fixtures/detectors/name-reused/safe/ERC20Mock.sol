// safe: the testing stub has its own name.
pragma solidity ^0.8.0;

contract ERC20Mock {
    mapping(address => uint256) public balanceOf;

    function setBalance(address who, uint256 amount) external {
        balanceOf[who] = amount;
    }
}
