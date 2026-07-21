// vulnerable: locals reuse names of a state variable, a function and an event.
pragma solidity ^0.8.0;

contract Vault {
    uint256 public total;

    event Deposit(address who, uint256 amount);

    function deposit() external payable {
        total += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // The parameter shadows the state variable `total`: the body updates the
    // parameter, not the storage variable.
    function report(uint256 total) external view returns (uint256) {
        return total + 1;
    }

    // The local shadows the function name `deposit`.
    function broken() external {
        uint256 deposit;
        deposit = 2;
        total += deposit;
    }
}
