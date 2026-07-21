// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: the modern equivalents of every deprecated construct.
contract Modern {
    function h() public view returns (uint256) {
        return block.timestamp; // SAFE: not `now`
    }

    function digest(bytes memory data) public pure returns (bytes32) {
        return keccak256(data); // SAFE: not sha3
    }

    function remainingGas() public view returns (uint256) {
        return gasleft(); // SAFE: not msg.gas
    }

    function blockHash(uint256 n) public view returns (bytes32) {
        return blockhash(n); // SAFE: not block.blockhash
    }
}

error Unauthorized();

/// SAFE (FP regression): `revert CustomError(...)` is the modern,
/// non-deprecated form of aborting — it is NOT the legacy `throw`.
contract ModernRevert {
    function restricted(bool ok) external pure {
        if (!ok) {
            revert Unauthorized(); // SAFE: modern revert, not `throw`
        }
    }
}
