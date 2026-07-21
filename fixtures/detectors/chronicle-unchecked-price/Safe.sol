// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Original minimal mock of the Chronicle oracle interface.
interface IChronicle {
    function tryRead() external view returns (uint256 value, bool valid);

    function readWithAge() external view returns (uint256 value, uint256 age);
}

/// Original fixture: Chronicle reads guarded by a validity/age check.
contract Pricer {
    uint256 public constant MAX_AGE = 3600;

    /// SAFE: tryRead surfaces the validity flag, which is checked.
    function ethUsd(IChronicle feed) external view returns (uint256) {
        (uint256 value, bool valid) = feed.tryRead();
        require(valid, "feed invalid");
        return value;
    }

    /// SAFE: readWithAge surfaces the age, which is bounded.
    function fresh(IChronicle feed) external view returns (uint256) {
        (uint256 value, uint256 age) = feed.readWithAge();
        require(age <= MAX_AGE, "feed stale");
        return value;
    }
}
