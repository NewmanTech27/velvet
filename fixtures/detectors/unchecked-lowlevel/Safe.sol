// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// SAFE fixture: low-level call results are checked or logged.
contract SafePayroll {
    event PaymentResult(bool success);

    /// SAFE: success flag captured and required.
    function pay(address payable employee, uint256 salary) external {
        (bool ok, ) = employee.call{value: salary}("");
        require(ok, "payment failed");
    }

    /// SAFE: success flag deliberately logged.
    function payLogged(address payable employee, uint256 salary) external {
        (bool ok, ) = employee.call{value: salary}("");
        emit PaymentResult(ok);
    }

    /// SAFE: failure handled through an if-condition.
    function payConditional(address payable employee, uint256 salary) external returns (bool) {
        (bool ok, ) = employee.call{value: salary}("");
        if (!ok) {
            return false;
        }
        return true;
    }
}
