// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: assert conditions with embedded side effects.
contract Counter {
    uint256 public n;

    function bump() external {
        assert((n += 1) > 0); // VULNERABLE: assignment inside the invariant
    }

    function bumpBounded() external {
        assert(n++ < 100); // VULNERABLE: increment inside the invariant
    }

    function callChecked() external {
        assert(mutate() >= 0); // VULNERABLE: mutating call inside the invariant
    }

    function mutate() public returns (int256) {
        n += 1;
        return int256(n);
    }
}
