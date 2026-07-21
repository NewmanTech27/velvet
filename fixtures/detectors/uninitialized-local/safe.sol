// safe: dst is assigned on every path before it is read.
pragma solidity ^0.8.0;

contract Payout {
    function pay(bool useAlt, address alt, address fallbackTo) external {
        address payable dst;
        if (useAlt) {
            dst = payable(alt);
        } else {
            dst = payable(fallbackTo);
        }
        dst.transfer(1 ether);
    }

    // safe: ptr is assigned inside the inline assembly block before use.
    function buffer() external pure returns (uint256 result) {
        uint256 ptr;
        assembly {
            ptr := add(0x20, 0x40)
        }
        result = ptr;
    }

    // safe: the for-header declaration establishes the counter's value.
    function sumUpTo(uint256 n) external pure returns (uint256 total) {
        for (uint256 i; i < n; ++i) {
            total += i;
        }
    }
}
