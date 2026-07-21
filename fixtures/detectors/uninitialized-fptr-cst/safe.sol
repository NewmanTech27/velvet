// safe: the pointer is assigned before the constructor calls it; calls from
// regular functions are outside this detector's scope.
pragma solidity 0.5.8;

contract Init {
    uint256 public result;

    constructor() public {
        function(uint256) internal returns (uint256) cb;
        cb = double;
        result = cb(2);
    }

    function double(uint256 v) internal pure returns (uint256) {
        return v * 2;
    }

    function callIt(function(uint256) internal returns (uint256) cb)
        internal
        returns (uint256)
    {
        // parameter pointers are assigned by the caller: not uninitialized.
        return cb(1);
    }
}
