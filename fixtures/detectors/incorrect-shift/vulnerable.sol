// vulnerable: shl/shr/sar called with the value first and the amount second.
pragma solidity ^0.8.0;

contract Bits {
    // Intended: word >> 248 (keep the top byte). Written swapped.
    function lowByte(uint256 word) external pure returns (uint256 r) {
        assembly {
            r := shr(word, 248)
        }
    }

    // Intended: x >> 255 (sign bit). Written swapped.
    function signBit(int256 x) external pure returns (uint256 r) {
        assembly {
            r := sar(x, 255)
        }
    }

    // Intended: v << 4. Written swapped.
    function times16(uint256 v) external pure returns (uint256 r) {
        assembly {
            r := shl(v, 4)
        }
    }
}
