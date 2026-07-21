pragma solidity ^0.8.0;

// Safe: the same pattern compiled with a fixed compiler (>= 0.5.10) — the
// encoder bug does not apply, so no finding is expected.
contract NestedEncoderFixed {
    uint256[2][2] public matrix = [[10, 20], [30, 40]];

    function packed() external view returns (bytes memory) {
        return abi.encode(matrix);
    }
}
