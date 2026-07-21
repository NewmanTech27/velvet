// vulnerable: beneficiary is never set anywhere but is read.
pragma solidity ^0.8.0;

contract Fundraiser {
    // never assigned at declaration, in the constructor, or by any function.
    address payable public beneficiary;

    function donate() external payable {
        // sends every donation to address(0).
        beneficiary.transfer(msg.value);
    }
}
