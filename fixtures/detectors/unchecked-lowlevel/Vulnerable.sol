// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: low-level call success values discarded.
contract Payroll {
    /// VULNERABLE: the call result is not even captured.
    function pay(address payable employee, uint256 salary) external {
        employee.call{value: salary}("");
    }

    /// VULNERABLE: captured but never checked or consumed.
    function payCapture(address payable employee, uint256 salary) external {
        (bool ok, ) = employee.call{value: salary}("");
    }
}
