// safe (fixed compiler): solc >= 0.5.9 rejects uninitialized pointer calls;
// here the pointer is bound at declaration anyway.
pragma solidity ^0.8.0;

contract Init {
    uint256 public result;

    constructor() {
        function(uint256) internal returns (uint256) cb = double;
        result = cb(2);
    }

    function double(uint256 v) internal pure returns (uint256) {
        return v * 2;
    }
}
