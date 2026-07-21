// vulnerable: Ether can be sent in but never out.
pragma solidity ^0.8.0;

contract TipJar {
    mapping(address => uint256) public tips;

    // payable, but there is no transfer/send/call/selfdestruct anywhere.
    function tip() external payable {
        tips[msg.sender] += msg.value;
    }
}
