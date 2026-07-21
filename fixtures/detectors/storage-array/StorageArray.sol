pragma solidity 0.5.8;

// Vulnerable (on this compiler): negative literals assigned into a signed
// integer storage array; solc 0.4.7-0.5.9 mis-encode the sign.
contract SignedScores {
    int256[4] public values;

    function reset() external {
        values = [int256(-1), -1, -1, -1]; // stored incorrectly
    }

    function setOne() external {
        values[0] = -2; // element-level negative assignment
    }
}

// Safe even on the affected compiler: positive values only, and an
// unsigned array.
contract PositiveScores {
    int256[4] public values;
    uint256[4] public unsignedValues;

    function reset() external {
        values = [int256(1), 1, 1, 1];
    }

    function resetUnsigned() external {
        unsignedValues = [uint256(1), 1, 1, 1];
    }
}
