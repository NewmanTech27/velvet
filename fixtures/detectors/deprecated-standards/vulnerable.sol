// vulnerable: `now` is deprecated (removed in solc 0.7.0) — the only
// deprecated construct still accepted by a compiler velvet can parse
// (0.5.x-0.6.x). The remaining constructs (throw, sha3, suicide, callcode,
// msg.gas, block.blockhash, var, years, the `constant` function modifier)
// predate the ASTs velvet parses and are covered by scanner-level tests.
pragma solidity 0.6.12;

contract Old {
    uint256 public lastSeen;

    function touch() external {
        lastSeen = now; // VULNERABLE: use block.timestamp
    }

    function stale(uint256 deadline) external view returns (bool) {
        return now > deadline; // VULNERABLE: use block.timestamp
    }
}
