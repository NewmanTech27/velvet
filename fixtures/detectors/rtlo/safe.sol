// safe: no bidirectional override characters anywhere.
pragma solidity ^0.8.0;

contract Pay {
    function sweep(address to, uint256 amount) external {
        // a plain remark.
        payable(to).transfer(amount);
    }
}
