// safe: every contract name in the compilation unit is unique.
pragma solidity ^0.8.0;

contract ERC20 {
    mapping(address => uint256) public balanceOf;

    function mint(uint256 amount) external {
        balanceOf[msg.sender] += amount;
    }
}
