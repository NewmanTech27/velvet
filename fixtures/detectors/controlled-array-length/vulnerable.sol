// vulnerable: array.length assigned from user-controlled input (solc < 0.6).
pragma solidity 0.5.8;

contract Pool {
    uint256[] public entries;
    address public owner = msg.sender;

    function resize(uint256 n) external {
        entries.length = n;
    }

    function set(uint256 i, uint256 v) external {
        entries[i] = v;
    }
}
