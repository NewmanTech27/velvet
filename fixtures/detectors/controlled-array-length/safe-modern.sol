// safe (fixed compiler): solc >= 0.6.0 has no array.length assignment;
// arrays grow via push, and .length is only ever read.
pragma solidity ^0.8.0;

contract Pool {
    uint256[] public entries;

    function add(uint256 v) external {
        entries.push(v);
    }

    function size() external view returns (uint256) {
        return entries.length;
    }
}
