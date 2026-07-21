pragma solidity ^0.8.0;

// Safe: negative assignments into a signed storage array compiled with a
// fixed compiler (>= 0.5.10) — the sign-encoding bug does not apply.
contract SignedScoresFixed {
    int256[4] public values;

    function reset() external {
        values = [int256(-1), -1, -1, -1];
    }
}
