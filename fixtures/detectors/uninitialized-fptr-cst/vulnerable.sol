// vulnerable: the constructor calls a function pointer that was never set.
pragma solidity 0.5.8;

contract Init {
    uint256 public result;

    constructor() public {
        function(uint256) internal returns (uint256) cb;
        // cb is uninitialized: the jump target is zero and deployment reverts.
        result = cb(1);
    }

    function double(uint256 v) internal pure returns (uint256) {
        return v * 2;
    }
}
