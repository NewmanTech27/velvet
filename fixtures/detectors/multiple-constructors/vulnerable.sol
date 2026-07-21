// vulnerable: both constructor styles in one contract.
// NOTE: only solc 0.4.22 accepts this source; modern solc rejects it, so the
// pattern is exercised by the test suite through a constructed model instead.
pragma solidity 0.4.22;

contract Token {
    uint256 public supply;

    constructor() public {
        supply = 1000;
    }

    function Token() public {
        supply = 1;
    }
}
