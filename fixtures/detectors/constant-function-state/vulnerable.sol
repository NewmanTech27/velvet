// vulnerable: a constant function that changes state through ordinary
// Solidity statements.
// NOTE: only solc < 0.5 accepts this source (0.5+ enforces view/pure), and
// velvet's parser requires the compact AST of solc >= 0.5, so the pattern
// is exercised by the test suite through a constructed model instead.
pragma solidity ^0.4.24;

contract Stats {
    uint256 public queries;

    function total() external constant returns (uint256) {
        queries += 1; // writes state in a constant function (allowed pre-0.5)
        return queries;
    }
}
