// vulnerable: dst is read on a path where it was never assigned.
pragma solidity ^0.8.0;

contract Payout {
    // When useAlt is false, dst is never assigned and the transfer goes to
    // address(0).
    function pay(bool useAlt, address alt) external {
        address payable dst;
        if (useAlt) {
            dst = payable(alt);
        }
        dst.transfer(1 ether);
    }
}
