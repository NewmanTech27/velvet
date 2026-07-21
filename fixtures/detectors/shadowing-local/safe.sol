// safe: locals use distinct names.
pragma solidity ^0.8.0;

contract Vault {
    uint256 public total;

    event Deposit(address who, uint256 amount);

    function deposit() external payable {
        total += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function report(uint256 subtotal) external view returns (uint256) {
        return subtotal + 1;
    }

    function sweep() external {
        uint256 depositAmount = 2;
        total += depositAmount;
    }
}
