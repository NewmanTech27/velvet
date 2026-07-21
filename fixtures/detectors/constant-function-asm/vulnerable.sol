// vulnerable: a constant function whose assembly mutates state.
// NOTE: only solc < 0.5 accepts this source (0.5+ enforces view/pure), and
// velvet's parser requires the compact AST of solc >= 0.5, so the pattern
// is exercised by the test suite through a constructed model instead.
pragma solidity ^0.4.24;

contract Counter {
    uint256 public n;

    function readAndBump() external constant returns (uint256) {
        assembly { sstore(0, add(sload(0), 1)) } // state change in a constant function
        return n;
    }
}
