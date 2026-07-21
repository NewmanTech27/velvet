pragma solidity 0.5.8;

// Vulnerable (on this compiler): a storage array of arrays is passed to
// abi.encode; solc 0.4.7-0.5.9 mis-encode it with an off-by-one shift.
contract NestedEncoder {
    uint256[2][2] public matrix = [[10, 20], [30, 40]];

    function packed() external view returns (bytes memory) {
        return abi.encode(matrix); // mis-encoded by the buggy encoder
    }
}

// Safe even on the affected compiler: only a one-dimensional array is
// encoded.
contract FlatEncoder {
    uint256[2] public row = [1, 2];

    function packed() external view returns (bytes memory) {
        return abi.encode(row);
    }
}
