// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original fixture: division before multiplication truncates precision.
contract Rewards {
    /// VULNERABLE: (principal / 365) truncates to 0 for principal < 365.
    function reward(uint256 principal, uint256 daysStaked) external pure returns (uint256) {
        return (principal / 365) * daysStaked;
    }

    /// VULNERABLE: same pattern through an intermediate local.
    function fee(uint256 amount, uint256 periods) external pure returns (uint256) {
        uint256 perDay = amount / 365;
        return perDay * periods;
    }

    /// VULNERABLE: the truncated product feeds further arithmetic — the
    /// round-down idiom exclusion does not apply inside a subtraction.
    function spread(uint256 total, uint256 unit) external pure returns (uint256) {
        uint256 quotient = total / unit;
        return total - unit * quotient;
    }

    /// VULNERABLE: division performed in inline assembly, then multiplied.
    function scaled(uint256 a, uint256 b) external pure returns (uint256 r) {
        assembly {
            r := div(a, b)
        }
        return 3 * r;
    }
}
