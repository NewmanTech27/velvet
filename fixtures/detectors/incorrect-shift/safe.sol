// safe: shift amount first, value second (the Yul operand order).
pragma solidity ^0.8.0;

contract Bits {
    function lowByte(uint256 word) external pure returns (uint256 r) {
        assembly {
            r := shr(248, word)
        }
    }

    function signBit(int256 x) external pure returns (uint256 r) {
        assembly {
            r := sar(255, x)
        }
    }

    // Variable amount: not a literal, so no obviously-swapped order.
    function shiftBy(uint256 v, uint256 amount) external pure returns (uint256 r) {
        assembly {
            r := shl(amount, v)
        }
    }
}
