// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

/// Original fixture: second file with a different pragma constraint.
contract TokenB {
    string public name = "B";

    function rename(string calldata next) external {
        name = next;
    }
}
