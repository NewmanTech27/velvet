// A testing stub that accidentally ships the same contract name.
pragma solidity ^0.8.0;

contract ERC20 {
    mapping(address => uint256) public balanceOf;

    // The stub lets anyone set any balance; it must never be deployed.
    function setBalance(address who, uint256 amount) external {
        balanceOf[who] = amount;
    }
}
