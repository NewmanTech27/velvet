// vulnerable: integer-to-enum conversion of user input with solc < 0.4.5
// (no range check: State(7) is silently accepted).
// NOTE: only solc < 0.4.5 exhibits the bug; velvet's parser requires the
// compact AST of solc >= 0.5, so the pattern is exercised by the test
// suite through a constructed model instead.
pragma solidity 0.4.2;

contract Machine {
    enum State { Off, On }

    function set(uint256 s) external pure returns (State) {
        return State(s); // no range check in old solc
    }
}
